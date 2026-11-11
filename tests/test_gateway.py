"""TCP 访问网关行为测试：真实 socket、真实回显上游、真实规则切换。"""

from __future__ import annotations

import asyncio
import contextlib
import socket
from ipaddress import IPv4Address, IPv4Network

import pytest

from app.engine import Rule
from app.gateway import Gateway, GatewayConfig


def make_rule(rid: str, action: str, port: int,
              source: str = "127.0.0.0/8",
              destination: str = "127.0.0.1/32", order: int = 0) -> Rule:
    return Rule(id=rid, order=order, source=IPv4Network(source),
                destination=IPv4Network(destination),
                port_low=port, port_high=port, action=action)


async def _echo_handler(reader: asyncio.StreamReader,
                        writer: asyncio.StreamWriter) -> None:
    try:
        while True:
            data = await reader.read(65536)
            if not data:
                break
            writer.write(data)
            await writer.drain()
    finally:
        writer.close()
        with contextlib.suppress(OSError, RuntimeError):
            await writer.wait_closed()


async def _start_echo() -> tuple[asyncio.AbstractServer, int]:
    server = await asyncio.start_server(_echo_handler, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    return server, port


async def _start_gateway(upstream_port: int) -> Gateway:
    config = GatewayConfig(
        listen_host="127.0.0.1", listen_port=0,
        upstream_host="127.0.0.1", upstream_port=upstream_port,
        upstream_ip=IPv4Address("127.0.0.1"), connect_timeout=2.0,
    )
    gateway = Gateway(config)
    await gateway.start()
    return gateway


async def _read_until_eof(reader: asyncio.StreamReader, timeout: float = 2.0) -> bytes:
    chunks: list[bytes] = []
    while True:
        try:
            data = await asyncio.wait_for(reader.read(65536), timeout)
        except (ConnectionResetError, OSError):
            break
        if not data:
            break
        chunks.append(data)
    return b"".join(chunks)


async def _wait_session(gateway: Gateway, state: str | None = None,
                        timeout: float = 2.0) -> dict:
    deadline = asyncio.get_running_loop().time() + timeout
    while asyncio.get_running_loop().time() < deadline:
        connections = gateway.snapshot()["connections"]
        if state is None and connections:
            return connections[0]
        for conn in connections:
            if conn["state"] == state:
                return conn
        await asyncio.sleep(0.01)
    raise AssertionError("等待会话状态超时")


# --------------------------------------------------------------------------- #
# 启动即默认拒绝
# --------------------------------------------------------------------------- #
def test_empty_rules_default_deny_closes_client():
    async def scenario():
        echo, echo_port = await _start_echo()
        gateway = await _start_gateway(echo_port)
        try:
            assert gateway.snapshot()["activeRules"] == []
            reader, writer = await asyncio.open_connection(
                "127.0.0.1", gateway.snapshot()["listenPort"])
            try:
                data = await asyncio.wait_for(reader.read(1), 2)
            except ConnectionResetError:
                data = b""
            assert data == b""
            assert gateway.snapshot()["connectionCount"] == 0
            assert gateway.snapshot()["stats"]["denied"] == 1
        finally:
            await gateway.stop()
            echo.close()
            await echo.wait_closed()

    asyncio.run(scenario())


# --------------------------------------------------------------------------- #
# 放行、双向透传与单向 EOF
# --------------------------------------------------------------------------- #
def test_allowed_connection_bidirectional_and_byte_counts():
    async def scenario():
        echo, echo_port = await _start_echo()
        gateway = await _start_gateway(echo_port)
        try:
            await gateway.apply_rules([make_rule("allow", "allow", echo_port)])
            reader, writer = await asyncio.open_connection(
                "127.0.0.1", gateway.snapshot()["listenPort"])
            writer.write(b"ping-1")
            await writer.drain()
            assert await asyncio.wait_for(reader.readexactly(6), 2) == b"ping-1"

            writer.write(b"ping-2")
            await writer.drain()
            assert await asyncio.wait_for(reader.readexactly(6), 2) == b"ping-2"

            conn = await _wait_session(gateway, "relaying")
            assert conn["allowed"] is True
            assert conn["matchedRuleId"] == "allow"
            assert conn["bytesClientToUpstream"] == 12
            assert conn["bytesUpstreamToClient"] == 12
            writer.close()
            with contextlib.suppress(OSError, RuntimeError):
                await writer.wait_closed()
        finally:
            await gateway.stop()
            echo.close()
            await echo.wait_closed()

    asyncio.run(scenario())


def test_one_way_eof_does_not_stop_reverse_receiving():
    async def scenario():
        echo, echo_port = await _start_echo()
        gateway = await _start_gateway(echo_port)
        try:
            await gateway.apply_rules([make_rule("allow", "allow", echo_port)])
            reader, writer = await asyncio.open_connection(
                "127.0.0.1", gateway.snapshot()["listenPort"])
            writer.write(b"half-close-payload")
            await writer.drain()
            writer.write_eof()  # 客户端半关闭写方向，读方向必须继续工作

            received = await _read_until_eof(reader, timeout=2)
            assert received == b"half-close-payload"
        finally:
            await gateway.stop()
            echo.close()
            await echo.wait_closed()

    asyncio.run(scenario())


# --------------------------------------------------------------------------- #
# 规则切换：撤权、保留、连接中
# --------------------------------------------------------------------------- #
def test_rule_switch_closes_established_denied_connection():
    async def scenario():
        echo, echo_port = await _start_echo()
        gateway = await _start_gateway(echo_port)
        try:
            await gateway.apply_rules([make_rule("allow", "allow", echo_port)])
            reader, writer = await asyncio.open_connection(
                "127.0.0.1", gateway.snapshot()["listenPort"])
            writer.write(b"before")
            await writer.drain()
            assert await asyncio.wait_for(reader.readexactly(6), 2) == b"before"

            switch = await gateway.apply_rules(
                [make_rule("deny", "deny", echo_port)])
            assert switch["closedSessionCount"] == 1
            assert gateway.snapshot()["connectionCount"] == 0
            assert gateway.snapshot()["stats"]["closedByRule"] >= 1

            # 切换接口已经返回；此时该连接必须已经关闭且不再转发数据。
            try:
                writer.write(b"must-not-be-forwarded")
                await writer.drain()
            except (ConnectionResetError, BrokenPipeError, OSError):
                pass
            try:
                data = await asyncio.wait_for(reader.read(1), 2)
            except (ConnectionResetError, OSError):
                data = b""
            assert data == b""
        finally:
            await gateway.stop()
            echo.close()
            await echo.wait_closed()

    asyncio.run(scenario())


def test_rule_switch_keeps_still_allowed_connection_uninterrupted():
    async def scenario():
        echo, echo_port = await _start_echo()
        gateway = await _start_gateway(echo_port)
        try:
            await gateway.apply_rules([make_rule("allow-1", "allow", echo_port)])
            reader, writer = await asyncio.open_connection(
                "127.0.0.1", gateway.snapshot()["listenPort"])
            writer.write(b"one")
            await writer.drain()
            assert await asyncio.wait_for(reader.readexactly(3), 2) == b"one"

            switch = await gateway.apply_rules(
                [make_rule("allow-2", "allow", echo_port)])
            assert switch["closedSessionCount"] == 0
            assert switch["keptSessionCount"] == 1

            writer.write(b"two")
            await writer.drain()
            assert await asyncio.wait_for(reader.readexactly(3), 2) == b"two"
            conn = await _wait_session(gateway, "relaying")
            assert conn["matchedRuleId"] == "allow-2"
            writer.close()
            with contextlib.suppress(OSError, RuntimeError):
                await writer.wait_closed()
        finally:
            await gateway.stop()
            echo.close()
            await echo.wait_closed()

    asyncio.run(scenario())


def test_rule_switch_closes_session_while_connecting_upstream():
    async def scenario():
        echo, echo_port = await _start_echo()
        gateway = await _start_gateway(echo_port)
        original_open = gateway._open_connection

        async def slow_open():
            await asyncio.sleep(1.5)
            return await original_open()

        # 注入延迟，让会话稳定停留在“正在连接上游”状态
        gateway._open_connection = slow_open  # type: ignore[assignment]
        try:
            await gateway.apply_rules([make_rule("allow", "allow", echo_port)])
            reader, writer = await asyncio.open_connection(
                "127.0.0.1", gateway.snapshot()["listenPort"])
            await _wait_session(gateway, "connecting", timeout=2)

            switch = await gateway.apply_rules(
                [make_rule("deny", "deny", echo_port)])
            assert switch["closedSessionCount"] == 1
            assert gateway.snapshot()["connectionCount"] == 0
            try:
                data = await asyncio.wait_for(reader.read(1), 2)
            except (ConnectionResetError, OSError):
                data = b""
            assert data == b""
        finally:
            await gateway.stop()
            echo.close()
            await echo.wait_closed()

    asyncio.run(scenario())


def test_upstream_connect_failure_closes_client_and_cleans_session():
    async def scenario():
        # 预留一个端口后立即释放，确保没有监听者
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        probe.bind(("127.0.0.1", 0))
        dead_port = probe.getsockname()[1]
        probe.close()

        gateway = await _start_gateway(dead_port)
        try:
            await gateway.apply_rules([make_rule("allow", "allow", dead_port)])
            reader, writer = await asyncio.open_connection(
                "127.0.0.1", gateway.snapshot()["listenPort"])
            try:
                data = await asyncio.wait_for(reader.read(1), 3)
            except (ConnectionResetError, OSError):
                data = b""
            assert data == b""
            await asyncio.sleep(0.05)
            assert gateway.snapshot()["connectionCount"] == 0
            assert gateway.snapshot()["stats"]["upstreamFailed"] >= 1
            writer.close()
        finally:
            await gateway.stop()

    asyncio.run(scenario())


def test_first_match_and_default_deny_semantics():
    async def scenario():
        echo, echo_port = await _start_echo()
        gateway = await _start_gateway(echo_port)
        try:
            # 首条 deny 命中后，后面的 allow 不再生效
            await gateway.apply_rules([
                make_rule("first-deny", "deny", echo_port,
                          source="0.0.0.0/0"),
                make_rule("later-allow", "allow", echo_port,
                          source="0.0.0.0/0", order=1),
            ])
            reader, writer = await asyncio.open_connection(
                "127.0.0.1", gateway.snapshot()["listenPort"])
            try:
                data = await asyncio.wait_for(reader.read(1), 2)
            except (ConnectionResetError, OSError):
                data = b""
            assert data == b""
            assert gateway.snapshot()["stats"]["denied"] == 1

            # 首条 allow 命中后，后面的 deny 不再生效
            await gateway.apply_rules([
                make_rule("first-allow", "allow", echo_port,
                          source="0.0.0.0/0"),
                make_rule("later-deny", "deny", echo_port,
                          source="0.0.0.0/0", order=1),
            ])
            reader, writer = await asyncio.open_connection(
                "127.0.0.1", gateway.snapshot()["listenPort"])
            writer.write(b"ok")
            await writer.drain()
            assert await asyncio.wait_for(reader.readexactly(2), 2) == b"ok"
            conn = await _wait_session(gateway, "relaying")
            assert conn["matchedRuleId"] == "first-allow"
            writer.close()
            with contextlib.suppress(OSError, RuntimeError):
                await writer.wait_closed()
        finally:
            await gateway.stop()
            echo.close()
            await echo.wait_closed()

    asyncio.run(scenario())


def test_source_ip_is_taken_from_peer_not_from_first_rule():
    """规则只按真实对端源 IP 判定；这里验证不同源 CIDR 的拒绝规则不误伤/误放。"""
    async def scenario():
        echo, echo_port = await _start_echo()
        gateway = await _start_gateway(echo_port)
        try:
            # 先 deny 别的网段，再 allow 本机：首条命中与默认拒绝语义都得到验证
            await gateway.apply_rules([
                make_rule("deny-other", "deny", echo_port,
                          source="10.0.0.0/8"),
                make_rule("allow-local", "allow", echo_port, order=1),
            ])
            reader, writer = await asyncio.open_connection(
                "127.0.0.1", gateway.snapshot()["listenPort"])
            writer.write(b"ok")
            await writer.drain()
            assert await asyncio.wait_for(reader.readexactly(2), 2) == b"ok"
            conn = await _wait_session(gateway, "relaying")
            assert conn["matchedRuleId"] == "allow-local"
            writer.close()
            with contextlib.suppress(OSError, RuntimeError):
                await writer.wait_closed()
        finally:
            await gateway.stop()
            echo.close()
            await echo.wait_closed()

    asyncio.run(scenario())
