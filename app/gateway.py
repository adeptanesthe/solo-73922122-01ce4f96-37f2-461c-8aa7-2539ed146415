"""TCP 访问网关：按有序 IPv4/TCP 规则放行，并支持运行中原子切换规则。

核心约束
--------
* 上游 IPv4 地址与端口在启动时固定（环境变量配置），判定只使用
  内核提供的真实对端源 IP + 固定上游地址/端口，绝不读取客户端自报信息；
* 规则沿用规则差分台的格式：id / source / destination / portRange / action，
  首条命中生效，全部未命中即默认拒绝；最多 20 条；启动时规则为空；
* 获准连接在客户端与上游之间双向透传原始字节，任一方向的 EOF 只对
  该方向做半关闭，不影响反方向继续接收；
* 切换规则时同时覆盖“新建 / 已建立 / 正在连接上游”的会话：新规则拒绝
  的会话立即关闭，并在切换接口返回前终止其转发任务；仍获准的会话不中断；
* 非法规则不会进入本模块——调用方必须先完整校验，校验失败时活动规则
  与现有连接保持不变；
* 上游连接失败时关闭客户端一侧并清理会话。

本模块只应在一个事件循环中运行（单网关进程、单 uvicorn worker）。
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import os
import socket
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

from .engine import MAX_RULES, Rule, ValidationFailure, parse_ruleset

LOGGER = logging.getLogger("app.gateway")

CHUNK_SIZE = 64 * 1024
DEFAULT_CONNECT_TIMEOUT = 5.0


# --------------------------------------------------------------------------- #
# 配置
# --------------------------------------------------------------------------- #
def _env_first(*names: str, default: str) -> str:
    for name in names:
        value = os.environ.get(name)
        if value is not None and value.strip() != "":
            return value.strip()
    return default


def _env_int(*names: str, default: int) -> int:
    for name in names:
        value = os.environ.get(name)
        if value is None or not value.strip():
            continue
        try:
            return int(value, 10)
        except ValueError:
            LOGGER.warning("环境变量 %s 不是整数：%r，改用默认值 %r",
                           name, value, default)
    return default


def _resolve_ipv4(host: str) -> Optional[ipaddress.IPv4Address]:
    """把启动配置中的上游主机解析为固定 IPv4 地址（失败返回 None）。"""
    text = host.strip()
    try:
        return ipaddress.IPv4Address(text)
    except ipaddress.AddressValueError:
        pass
    try:
        infos = socket.getaddrinfo(text, None, family=socket.AF_INET,
                                   type=socket.SOCK_STREAM)
    except socket.gaierror:
        return None
    if not infos:
        return None
    try:
        return ipaddress.IPv4Address(infos[0][4][0])
    except (ipaddress.AddressValueError, IndexError):  # pragma: no cover
        return None


@dataclass
class GatewayConfig:
    """启动时固定的监听与上游配置。"""

    listen_host: str
    listen_port: int
    upstream_host: str
    upstream_port: int
    connect_timeout: float = DEFAULT_CONNECT_TIMEOUT
    upstream_ip: Optional[ipaddress.IPv4Address] = None
    resolve_error: Optional[str] = None

    @classmethod
    def from_env(cls) -> "GatewayConfig":
        listen_host = _env_first("GATEWAY_LISTEN_HOST", "GATEWAY_LISTEN_ADDR",
                                 "GATEWAY_BIND_HOST", "GATEWAY_HOST",
                                 "LISTEN_HOST", "BIND_HOST",
                                 default="127.0.0.1")
        listen_port = _env_int("GATEWAY_LISTEN_PORT", "GATEWAY_BIND_PORT",
                               "GATEWAY_TCP_PORT", "GATEWAY_PORT",
                               "LISTEN_PORT", "BIND_PORT", default=9001)
        upstream_host = _env_first("GATEWAY_UPSTREAM_HOST", "GATEWAY_UPSTREAM_IP",
                                   "GATEWAY_UPSTREAM_ADDR", "UPSTREAM_HOST",
                                   "UPSTREAM_IP", "UPSTREAM_ADDR",
                                   "TARGET_HOST", default="127.0.0.1")
        upstream_port = _env_int("GATEWAY_UPSTREAM_PORT", "UPSTREAM_PORT",
                                 "TARGET_PORT", default=9000)
        try:
            timeout = float(_env_first("GATEWAY_CONNECT_TIMEOUT",
                                       default=str(DEFAULT_CONNECT_TIMEOUT)))
        except ValueError:
            timeout = DEFAULT_CONNECT_TIMEOUT

        upstream_ip = _resolve_ipv4(upstream_host)
        resolve_error = None
        if upstream_ip is None:
            resolve_error = f"无法把上游主机 {upstream_host!r} 解析为 IPv4 地址"
            LOGGER.warning(resolve_error)
        return cls(listen_host=listen_host, listen_port=listen_port,
                   upstream_host=upstream_host, upstream_port=upstream_port,
                   connect_timeout=max(0.01, timeout),
                   upstream_ip=upstream_ip, resolve_error=resolve_error)

    def refresh_upstream(self) -> Optional[ipaddress.IPv4Address]:
        if self.upstream_ip is None:
            self.upstream_ip = _resolve_ipv4(self.upstream_host)
            self.resolve_error = None if self.upstream_ip else self.resolve_error
        return self.upstream_ip

    @property
    def upstream_address(self) -> str:
        return f"{self.upstream_host}:{self.upstream_port}"

    @property
    def upstream_ip_text(self) -> Optional[str]:
        return str(self.upstream_ip) if self.upstream_ip is not None else None


# --------------------------------------------------------------------------- #
# 规则校验 / 序列化
# --------------------------------------------------------------------------- #
def parse_gateway_rules(payload: Any) -> list[Rule]:
    """把 API 提交的规则（JSON 数组 / JSON 文本 / {"rules": ...}）校验为 Rule。

    任何格式或语义错误都抛 ``ValidationFailure``；调用方在成功返回前不得
    修改活动规则，从而保证非法提交不影响活动规则与连接。
    """
    if isinstance(payload, str):
        text = payload
    elif isinstance(payload, list):
        text = json.dumps(payload, ensure_ascii=False)
    elif isinstance(payload, dict):
        value: Any = None
        for key in ("rules", "ruleSet", "rulesText", "content", "text", "new"):
            if key in payload:
                value = payload[key]
                break
        if value is None:
            raise ValidationFailure([{
                "sheet": "gateway", "field": None,
                "message": "请求体缺少规则字段：请直接提交规则数组，"
                           "或使用 {\"rules\": [...]} / {\"rules\": \"<JSON文本>\"}",
            }])
        if isinstance(value, str):
            text = value
        elif isinstance(value, list):
            text = json.dumps(value, ensure_ascii=False)
        else:
            raise ValidationFailure([{
                "sheet": "gateway", "field": "rules",
                "message": f"rules 必须是规则数组或 JSON 文本，当前是 {type(value).__name__}",
            }])
    else:
        raise ValidationFailure([{
            "sheet": "gateway", "field": None,
            "message": "请求体必须是规则数组或包含 rules 字段的 JSON 对象",
        }])
    return parse_ruleset(text, "gateway")


def serialize_rule(rule: Rule) -> dict[str, Any]:
    """按原有规则格式输出（只保留管理员可编辑的五个字段）。"""
    return {
        "id": rule.id,
        "source": str(rule.source),
        "destination": str(rule.destination),
        "portRange": [rule.port_low, rule.port_high],
        "action": rule.action,
    }


def evaluate_rules(rules: list[Rule],
                   source_ip: ipaddress.IPv4Address,
                   upstream_ip: ipaddress.IPv4Address,
                   upstream_port: int) -> Optional[Rule]:
    """顺序扫描，首条命中生效；未命中返回 None（默认拒绝）。

    判定维度严格使用实际对端源 IP、启动配置固定下来的上游 IPv4 地址与端口。
    返回首条命中的规则（可能是 allow 或 deny）；调用方以 ``rule.action``
    决定是否放行，``None`` 表示默认拒绝。
    """
    for rule in rules:
        if (source_ip in rule.source
                and upstream_ip in rule.destination
                and rule.port_low <= upstream_port <= rule.port_high):
            return rule
    return None


def is_allow(rule: Optional[Rule]) -> bool:
    """首条命中规则动作是否为 allow（未命中即默认拒绝）。"""
    return rule is not None and rule.action == "allow"


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


# --------------------------------------------------------------------------- #
# 会话
# --------------------------------------------------------------------------- #
@dataclass
class Session:
    id: int
    client_ip: str
    client_port: int
    upstream_ip: str
    upstream_port: int
    created_at: str = field(default_factory=_iso_now)
    started_at_monotonic: float = field(default_factory=time.monotonic)
    state: str = "connecting"          # connecting / relaying / closed
    allowed: bool = False
    matched_rule_id: Any = None
    matched_rule_order: Optional[int] = None
    denied_reason: Optional[str] = None
    bytes_client_to_upstream: int = 0
    bytes_upstream_to_client: int = 0
    aborted: bool = False
    done_event: asyncio.Event = field(default_factory=asyncio.Event)
    connect_task: Optional[asyncio.Task] = None
    relay_tasks: list[asyncio.Task] = field(default_factory=list)
    client_writer: Optional[asyncio.StreamWriter] = None
    upstream_writer: Optional[asyncio.StreamWriter] = None

    @property
    def client_address(self) -> str:
        return f"{self.client_ip}:{self.client_port}"

    @property
    def upstream_address(self) -> str:
        return f"{self.upstream_ip}:{self.upstream_port}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "clientIp": self.client_ip,
            "clientPort": self.client_port,
            "clientAddress": self.client_address,
            "client": self.client_address,
            "sourceIp": self.client_ip,
            "upstreamIp": self.upstream_ip,
            "upstreamPort": self.upstream_port,
            "upstreamAddress": self.upstream_address,
            "upstream": self.upstream_address,
            "destinationIp": self.upstream_ip,
            "destinationPort": self.upstream_port,
            "state": self.state,
            "allowed": self.allowed,
            "matchedRuleId": self.matched_rule_id,
            "matchedRuleOrder": self.matched_rule_order,
            "ruleId": self.matched_rule_id,
            "deniedReason": self.denied_reason,
            "createdAt": self.created_at,
            "durationSeconds": round(time.monotonic() - self.started_at_monotonic, 3),
            "bytesClientToUpstream": self.bytes_client_to_upstream,
            "bytesUpstreamToClient": self.bytes_upstream_to_client,
            "clientToUpstreamBytes": self.bytes_client_to_upstream,
            "upstreamToClientBytes": self.bytes_upstream_to_client,
            "reason": self.denied_reason,
        }

    def abort(self, reason: str) -> None:
        """幂等地终止会话：标记拒绝、取消连接/转发任务并关闭两端 socket。"""
        if self.aborted:
            return
        self.aborted = True
        self.allowed = False
        self.denied_reason = reason
        if self.state != "closed":
            self.state = "closing"
        tasks = [self.connect_task] + list(self.relay_tasks)
        for task in tasks:
            if task is not None and not task.done():
                task.cancel()
        self._close_writers()

    def _close_writers(self) -> None:
        for writer in (self.client_writer, self.upstream_writer):
            if writer is not None:
                try:
                    writer.close()
                except (OSError, RuntimeError):  # pragma: no cover
                    pass

    async def wait_done(self, timeout: float) -> bool:
        try:
            await asyncio.wait_for(self.done_event.wait(), timeout)
            return True
        except asyncio.TimeoutError:  # pragma: no cover - 仅极端情况
            return False


# --------------------------------------------------------------------------- #
# 网关
# --------------------------------------------------------------------------- #
class Gateway:
    """单进程 TCP 访问网关。所有公开的异步方法必须在同一事件循环内调用。"""

    def __init__(self, config: Optional[GatewayConfig] = None):
        self.config = config or GatewayConfig.from_env()
        self._server: Optional[asyncio.AbstractServer] = None
        self._active_rules: list[Rule] = []
        self._sessions: dict[int, Session] = {}
        self._next_session_id = 1
        self._rule_lock = asyncio.Lock()
        self._running = False
        self._last_error: Optional[str] = None
        self._started_at: Optional[str] = None
        self._rules_version = 0
        self._rules_updated_at: Optional[str] = None
        self._stats: dict[str, int] = {
            "accepted": 0,
            "allowed": 0,
            "denied": 0,
            "upstreamFailed": 0,
            "closedByRule": 0,
            "currentlyActive": 0,
        }

    # ---------------------------- 生命周期 ---------------------------- #
    @property
    def running(self) -> bool:
        return self._running and self._server is not None

    async def start(self) -> None:
        if self._server is not None:
            return
        self.config.refresh_upstream()
        try:
            self._server = await asyncio.start_server(
                self._handle_client,
                host=self.config.listen_host,
                port=self.config.listen_port,
                family=socket.AF_INET,
            )
        except OSError as exc:
            self._last_error = f"TCP 网关监听失败：{exc}"
            LOGGER.error(self._last_error)
            self._server = None
            self._running = False
            return
        self._running = True
        self._last_error = None
        self._started_at = _iso_now()
        # 需求：启动时规则为空（默认拒绝）；同一进程内重启也回到空规则。
        self._active_rules = []
        self._rules_version = 0
        self._rules_updated_at = None
        self._stats = {
            "accepted": 0,
            "allowed": 0,
            "denied": 0,
            "upstreamFailed": 0,
            "closedByRule": 0,
            "currentlyActive": 0,
        }
        sockets = ", ".join(str(s.getsockname()) for s in self._server.sockets)
        LOGGER.info("TCP 网关已启动，监听 %s；上游固定为 %s:%s",
                    sockets, self.config.upstream_host,
                    self.config.upstream_port)

    async def stop(self) -> None:
        server = self._server
        self._server = None
        self._running = False
        if server is not None:
            server.close()
            try:
                await server.wait_closed()
            except (OSError, RuntimeError):  # pragma: no cover
                pass
        for session in list(self._sessions.values()):
            session.abort("gateway-stopping")
        await asyncio.gather(
            *(session.wait_done(2.0) for session in list(self._sessions.values())),
            return_exceptions=True,
        )
        self._sessions.clear()
        self._stats["currentlyActive"] = 0

    # ------------------------------ 状态 ------------------------------ #
    def active_rules(self) -> list[Rule]:
        return list(self._active_rules)

    def snapshot(self) -> dict[str, Any]:
        rules = [serialize_rule(r) for r in self._active_rules]
        connections = [s.to_dict() for s in sorted(
            self._sessions.values(), key=lambda item: item.id)]
        bound_port = self.config.listen_port
        if self._server is not None and self._server.sockets:
            try:
                bound_port = self._server.sockets[0].getsockname()[1]
            except (OSError, IndexError):  # pragma: no cover
                pass
        return {
            "ok": True,
            "running": self.running,
            "enabled": self.running,
            "listenHost": self.config.listen_host,
            "listenPort": bound_port,
            "upstreamHost": self.config.upstream_host,
            "upstreamIp": self.config.upstream_ip_text,
            "upstreamPort": self.config.upstream_port,
            "upstreamAddress": self.config.upstream_address,
            "upstreamResolveError": self.config.resolve_error,
            "activeRules": rules,
            "rules": rules,
            "ruleCount": len(rules),
            "maxRules": MAX_RULES,
            "rulesEnabled": bool(rules),
            "rulesVersion": self._rules_version,
            "rulesUpdatedAt": self._rules_updated_at,
            "connections": connections,
            "sessions": connections,
            "connectionCount": len(connections),
            "startedAt": self._started_at,
            "lastError": self._last_error,
            "config": {
                "listenHost": self.config.listen_host,
                "listenPort": bound_port,
                "upstreamHost": self.config.upstream_host,
                "upstreamIp": self.config.upstream_ip_text,
                "upstreamPort": self.config.upstream_port,
                "upstreamAddress": self.config.upstream_address,
                "connectTimeoutSeconds": self.config.connect_timeout,
            },
            "stats": dict(self._stats),
        }

    # -------------------------- 规则原子切换 -------------------------- #
    async def apply_rules(self, rules: list[Rule]) -> dict[str, Any]:
        """原子替换活动规则，并让新策略立即覆盖所有现存会话。

        * 新规则拒绝的会话：标记、关闭并等待其转发任务真正结束；
        * 仍获准的会话：不触碰，继续透传；
        * 正在连接上游的会话：取消其连接任务并关闭客户端。
        本协程返回后，被拒会话不会再向上游或客户端转发任何字节。
        """
        async with self._rule_lock:
            self._active_rules = list(rules)
            self._rules_version += 1
            self._rules_updated_at = _iso_now()
            upstream_ip = self.config.refresh_upstream()
            denied_sessions: list[Session] = []
            kept_count = 0
            for session in list(self._sessions.values()):
                rule = None
                if upstream_ip is not None:
                    rule = evaluate_rules(self._active_rules,
                                          ipaddress.IPv4Address(session.client_ip),
                                          upstream_ip,
                                          self.config.upstream_port)
                if not is_allow(rule):
                    session.allowed = False
                    session.matched_rule_id = None
                    session.matched_rule_order = None
                    session.abort("denied-by-rules")
                    denied_sessions.append(session)
                else:
                    # 仍获准：只更新命中的规则信息，不中断传输
                    kept_count += 1
                    session.allowed = True
                    session.matched_rule_id = rule.id
                    session.matched_rule_order = rule.order + 1
            if denied_sessions:
                self._stats["closedByRule"] += len(denied_sessions)

        # 在锁外等待，避免与正在连接上游的会话任务互相等待。
        if denied_sessions:
            await asyncio.gather(
                *(session.wait_done(5.0) for session in denied_sessions),
                return_exceptions=True,
            )
        return {
            "ruleCount": len(rules),
            "rulesVersion": self._rules_version,
            "rulesUpdatedAt": self._rules_updated_at,
            "closedSessionCount": len(denied_sessions),
            "closedSessionIds": [session.id for session in denied_sessions],
            "keptSessionCount": kept_count,
        }

    async def clear_rules(self) -> dict[str, Any]:
        return await self.apply_rules([])

    # ---------------------------- 会话控制 ---------------------------- #
    async def close_session(self, session_id: int, reason: str = "closed-by-admin") -> bool:
        session = self._sessions.get(session_id)
        if session is None:
            return False
        session.abort(reason)
        await session.wait_done(5.0)
        return True

    # ------------------------------ 接入 ------------------------------ #
    async def _handle_client(self, reader: asyncio.StreamReader,
                             writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername")
        client_ip = str(peer[0]) if peer else "0.0.0.0"
        client_port = int(peer[1]) if peer and len(peer) > 1 else 0
        try:
            source_ip = ipaddress.IPv4Address(client_ip)
        except ipaddress.AddressValueError:
            # 非 IPv4 对端：无法按 IPv4 规则判定，按默认拒绝处理
            source_ip = None

        session = Session(
            id=self._next_session_id,
            client_ip=client_ip,
            client_port=client_port,
            upstream_ip=self.config.upstream_ip_text or self.config.upstream_host,
            upstream_port=self.config.upstream_port,
        )
        session.client_writer = writer
        self._next_session_id += 1
        self._sessions[session.id] = session
        self._stats["accepted"] += 1
        self._stats["currentlyActive"] = len(self._sessions)

        try:
            upstream_ip = self.config.refresh_upstream()
            # 初始判定与注册都在同一个同步片段内完成，规则切换要么看到
            # 本会话、要么本会话看到新规则，不存在中间态。
            rule = None
            if source_ip is not None and upstream_ip is not None:
                rule = evaluate_rules(self._active_rules, source_ip,
                                      upstream_ip, self.config.upstream_port)
            if not is_allow(rule):
                session.denied_reason = (
                    "default-deny" if source_ip is not None and rule is None
                    else "denied-by-rule" if rule is not None
                    else "unsupported-address-family")
                if rule is not None:
                    session.matched_rule_id = rule.id
                    session.matched_rule_order = rule.order + 1
                self._stats["denied"] += 1
                return
            session.allowed = True
            session.matched_rule_id = rule.id
            session.matched_rule_order = rule.order + 1
            self._stats["allowed"] += 1

            await self._connect_and_relay(reader, session)
        except asyncio.CancelledError:
            # 仅当本会话任务被外部取消时继续向上传播；会话 abort 取消的是
            # connect/relay 子任务，由正常清理路径处理。
            raise
        except (OSError, RuntimeError) as exc:
            LOGGER.debug("会话 %s 结束：%s", session.id, exc)
        finally:
            session.state = "closed"
            session._close_writers()
            self._sessions.pop(session.id, None)
            self._stats["currentlyActive"] = len(self._sessions)
            session.done_event.set()

    async def _open_connection(self):
        """连接固定的上游 IPv4 地址（独立方法便于测试注入延迟）。"""
        return await asyncio.open_connection(
            host=str(self.config.upstream_ip),
            port=self.config.upstream_port,
            family=socket.AF_INET,
        )

    async def _connect_and_relay(self, reader: asyncio.StreamReader,
                                 session: Session) -> None:
        upstream_ip = self.config.refresh_upstream()
        if upstream_ip is None:
            session.abort("upstream-resolve-failed")
            self._stats["upstreamFailed"] += 1
            return

        session.state = "connecting"
        try:
            connect_task = asyncio.create_task(self._open_connection())
            session.connect_task = connect_task
            try:
                up_reader, up_writer = await asyncio.wait_for(
                    connect_task, timeout=self.config.connect_timeout)
            except asyncio.CancelledError:
                if session.aborted:
                    return
                raise
            except (OSError, asyncio.TimeoutError) as exc:
                # 上游连接失败：关闭客户端（两端均不再持有连接）并清理会话
                session.abort("upstream-connect-failed")
                self._stats["upstreamFailed"] += 1
                LOGGER.info("会话 %s 连接上游 %s 失败：%s", session.id,
                            self.config.upstream_address, exc)
                return
            finally:
                session.connect_task = None

            session.upstream_writer = up_writer
            # 连接建立期间可能已发生规则切换；切换逻辑会直接 abort 本会话。
            if session.aborted or not session.allowed:
                return

            # 上游连接成功返回后再次对照当前活动规则（防御性复核）。
            rule = evaluate_rules(
                self._active_rules,
                ipaddress.IPv4Address(session.client_ip),
                upstream_ip,
                self.config.upstream_port,
            )
            if not is_allow(rule):
                session.abort("denied-by-rules")
                self._stats["closedByRule"] += 1
                return
            session.allowed = True
            session.matched_rule_id = rule.id
            session.matched_rule_order = rule.order + 1

            session.state = "relaying"
            await self._relay(reader, up_reader, session, up_writer)
        finally:
            if session.connect_task is not None and not session.connect_task.done():
                session.connect_task.cancel()
                session.connect_task = None

    async def _relay(self, client_reader: asyncio.StreamReader,
                     upstream_reader: asyncio.StreamReader,
                     session: Session,
                     upstream_writer: asyncio.StreamWriter) -> None:
        client_writer = session.client_writer
        assert client_writer is not None

        to_upstream = asyncio.create_task(self._pump(
            client_reader, upstream_writer, session, "client-to-upstream"))
        to_client = asyncio.create_task(self._pump(
            upstream_reader, client_writer, session, "upstream-to-client"))
        session.relay_tasks = [to_upstream, to_client]
        try:
            done, pending = await asyncio.wait(
                {to_upstream, to_client}, return_when=asyncio.FIRST_EXCEPTION)
            failed = False
            for task in done:
                if task.cancelled():
                    continue
                exc = task.exception()
                if exc is not None:
                    failed = True
                    LOGGER.debug("会话 %s 转发异常：%r", session.id, exc)
            if failed or session.aborted:
                if not session.aborted:
                    session.abort("relay-error")
                for task in pending:
                    task.cancel()
            if pending:
                await asyncio.gather(*pending, return_exceptions=True)
            # 已结束任务的异常已经读取，避免 asyncio 的“未取异常”告警。
        finally:
            session.relay_tasks = []

    async def _pump(self, reader: asyncio.StreamReader,
                    writer: asyncio.StreamWriter, session: Session,
                    direction: str) -> None:
        """单向搬运；源方向 EOF 时只对目的方向 write_eof，反向任务继续。"""
        try:
            while not session.aborted:
                data = await reader.read(CHUNK_SIZE)
                if not data:
                    break
                if session.aborted or not session.allowed:
                    break
                writer.write(data)
                await writer.drain()
                if direction == "client-to-upstream":
                    session.bytes_client_to_upstream += len(data)
                else:
                    session.bytes_upstream_to_client += len(data)
        finally:
            # 单向 EOF：仅半关闭本方向的目标写端；绝不 close 整个连接。
            if not session.aborted:
                try:
                    writer.write_eof()
                except (OSError, RuntimeError):
                    pass


# --------------------------------------------------------------------------- #
# 应用内单例（由 FastAPI lifespan 启动，永远是单个网关进程）
# --------------------------------------------------------------------------- #
GATEWAY = Gateway()


def gateway_status() -> dict[str, Any]:
    return GATEWAY.snapshot()
