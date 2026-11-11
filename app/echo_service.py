"""本地 TCP 回显服务，用于演示与联调 TCP 访问网关。

用法::

    python -m app.echo_service --host 127.0.0.1 --port 9000

服务对每个连接原样回显收到的字节；客户端半关闭写方向后，服务会在
读完剩余数据后关闭对应连接。它是网关的“上游临时服务”，不参与规则判定。
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import logging
import signal

LOGGER = logging.getLogger("app.echo_service")


async def handle_echo(reader: asyncio.StreamReader,
                      writer: asyncio.StreamWriter) -> None:
    peer = writer.get_extra_info("peername")
    LOGGER.info("回显连接建立：%s", peer)
    try:
        while True:
            data = await reader.read(64 * 1024)
            if not data:
                break
            writer.write(data)
            await writer.drain()
    except (ConnectionError, OSError) as exc:
        LOGGER.debug("回显连接中断：%s", exc)
    finally:
        writer.close()
        with contextlib.suppress(OSError, RuntimeError):
            await writer.wait_closed()
        LOGGER.info("回显连接结束：%s", peer)


async def serve(host: str, port: int) -> None:
    server = await asyncio.start_server(handle_echo, host=host, port=port)
    sockets = ", ".join(str(s.getsockname()) for s in server.sockets)
    LOGGER.info("TCP 回显服务已启动：%s", sockets)
    stop_event = asyncio.Event()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        with contextlib.suppress(NotImplementedError):
            loop.add_signal_handler(sig, stop_event.set)

    async with server:
        await stop_event.wait()
    LOGGER.info("TCP 回显服务已停止")


def main() -> None:
    parser = argparse.ArgumentParser(description="本地 TCP 回显服务")
    parser.add_argument("--host", default="127.0.0.1",
                        help="监听地址，默认 127.0.0.1；容器内使用 0.0.0.0")
    parser.add_argument("--port", type=int, default=9000,
                        help="监听端口，默认 9000")
    args = parser.parse_args()
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    asyncio.run(serve(args.host, args.port))


if __name__ == "__main__":  # pragma: no cover
    main()
