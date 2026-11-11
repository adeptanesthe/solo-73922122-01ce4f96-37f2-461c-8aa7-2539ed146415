#!/usr/bin/env python3
"""长连接撤权演示：建立获准的 TCP 长连接，切换规则后观察其被立即断开。

前置条件（本地直连）::

    python -m app.echo_service --host 127.0.0.1 --port 9000 &
    GATEWAY_UPSTREAM_HOST=127.0.0.1 GATEWAY_UPSTREAM_PORT=9000 \
    GATEWAY_LISTEN_HOST=127.0.0.1 GATEWAY_LISTEN_PORT=9001 \
    uvicorn app.main:app --host 127.0.0.1 --port 8000

然后::

    python scripts/demo_revoke.py

Docker Compose 环境（规则中的源地址使用 0.0.0.0/0 即可）::

    docker compose up --build
    python scripts/demo_revoke.py --api-base http://127.0.0.1:8000 \
        --gateway-host 127.0.0.1 --gateway-port 9001

脚本会：启用全放行规则 → 建立连接并收发数据 → 启用拒绝规则 →
再次发送数据并确认连接被网关关闭。退出码 0 表示演示符合预期。
"""

from __future__ import annotations

import argparse
import json
import socket
import sys
import time
import urllib.error
import urllib.request

READ_TIMEOUT = 4.0


def api(base: str, method: str, path: str,
        payload: object | None = None) -> dict:
    data = None
    headers = {}
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(base.rstrip("/") + path, data=data,
                                 headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", "replace")
        raise SystemExit(f"HTTP {exc.code} {path}: {body}") from exc
    except urllib.error.URLError as exc:
        raise SystemExit(f"无法访问管理 API {base}: {exc}") from exc


def recv_expected(sock: socket.socket, expected: int) -> bytes:
    """读取至少 expected 字节（回显可能拆成多个 TCP 分片）。"""
    chunks = []
    total = 0
    while total < expected:
        data = sock.recv(4096)
        if not data:
            break
        chunks.append(data)
        total += len(data)
    return b"".join(chunks)


def is_closed(sock: socket.socket) -> bool:
    """在超时窗口内探测连接是否已被关闭（EOF / RST）。"""
    sock.settimeout(READ_TIMEOUT)
    try:
        data = sock.recv(1)
        return data == b""
    except socket.timeout:
        return False
    except (ConnectionResetError, BrokenPipeError, OSError):
        return True


def main() -> int:
    parser = argparse.ArgumentParser(description="TCP 网关长连接撤权演示")
    parser.add_argument("--api-base", default="http://127.0.0.1:8000")
    parser.add_argument("--gateway-host", default="127.0.0.1")
    parser.add_argument("--gateway-port", type=int, default=9001)
    args = parser.parse_args()

    status = api(args.api_base, "GET", "/api/gateway")
    upstream_port = int(status["upstreamPort"])
    print(f"[1] 网关状态：running={status['running']} "
          f"listen={status['listenHost']}:{status['listenPort']} "
          f"upstream={status['upstreamAddress']} 活动规则={status['ruleCount']}")

    allow_rule = [{
        "id": "demo-allow",
        "source": "0.0.0.0/0",
        "destination": "0.0.0.0/0",
        "portRange": [upstream_port, upstream_port],
        "action": "allow",
    }]
    result = api(args.api_base, "POST", "/api/gateway/rules", {"rules": allow_rule})
    print(f"[2] 已启用放行规则：{result['switch']['ruleCount']} 条，"
          f"关闭 {result['switch']['closedSessionCount']} 条旧连接")

    sock = socket.create_connection((args.gateway_host, args.gateway_port), timeout=5)
    sock.settimeout(READ_TIMEOUT)
    payload = b"hello over the gateway\n"
    sock.sendall(payload)
    echoed = recv_expected(sock, len(payload))
    if echoed != payload:
        print(f"    警告：回显内容不一致（收到 {echoed!r}）", file=sys.stderr)
    else:
        print(f"[3] 长连接已建立并双向透传：发送 {len(payload)} 字节，"
              f"收到回显 {len(echoed)} 字节")

    deny_rule = [{
        "id": "demo-deny",
        "source": "0.0.0.0/0",
        "destination": "0.0.0.0/0",
        "portRange": [upstream_port, upstream_port],
        "action": "deny",
    }]
    started = time.monotonic()
    result = api(args.api_base, "POST", "/api/gateway/rules", {"rules": deny_rule})
    elapsed = time.monotonic() - started
    print(f"[4] 已切换为拒绝规则：接口返回用时 {elapsed:.3f}s，"
          f"关闭 {result['switch']['closedSessionCount']} 条失去权限的连接")

    try:
        sock.sendall(b"should never be forwarded\n")
    except (ConnectionResetError, BrokenPipeError, OSError) as exc:
        print(f"[5] 再次发送数据失败（连接已关闭）：{type(exc).__name__}")
        return 0
    if is_closed(sock):
        print("[5] 再次发送数据后连接已关闭：撤权立即生效，旧数据不会继续转发")
        return 0

    print("[5] 失败：切换规则后长连接仍然可收发数据", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
