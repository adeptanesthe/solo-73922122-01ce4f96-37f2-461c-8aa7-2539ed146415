"""FastAPI 入口：规则差分页面、TCP 访问网关管理页与 JSON API。

TCP 网关与 Web 服务运行在同一个进程、同一个事件循环内（uvicorn 只使用
单个 worker）。启动时网关规则为空，所有连接按默认拒绝处理；管理员在
浏览器中编辑并“启用”规则后，新策略会原子地覆盖新建、已建立以及正在
连接上游的会话。
"""

from __future__ import annotations

import json
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .engine import MAX_RULES, ValidationFailure, analyze
from .example_data import EXAMPLE_PAYLOAD
from .gateway import (
    GATEWAY,
    parse_gateway_rules,
    serialize_rule,
)

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"


@asynccontextmanager
async def lifespan(_app: FastAPI):
    """单进程内启动唯一的 TCP 网关；关闭时终止全部会话。"""
    await GATEWAY.start()
    try:
        yield
    finally:
        await GATEWAY.stop()


app = FastAPI(
    title="防火墙规则变更差分台 · TCP 访问网关",
    description=(
        "精确比对两份有序 IPv4/TCP 规则集；并提供按同一规则语义运行的 "
        "TCP 访问网关，支持运行中原子切换规则并即时断开失去权限的长连接。"
    ),
    version="1.1.0",
    lifespan=lifespan,
)


class DiffRequest(BaseModel):
    old: str = Field(..., description="旧规则集 JSON 文本（数组，最多 20 条）")
    new: str = Field(..., description="新规则集 JSON 文本（数组，最多 20 条）")


# --------------------------------------------------------------------------- #
# 页面
# --------------------------------------------------------------------------- #
@app.get("/", include_in_schema=False)
def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/gateway", include_in_schema=False)
def gateway_page() -> FileResponse:
    """TCP 访问网关管理页（首页导航可直接进入）。"""
    return FileResponse(STATIC_DIR / "gateway.html")


app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


# --------------------------------------------------------------------------- #
# 规则差分 API（原有能力）
# --------------------------------------------------------------------------- #
@app.get("/api/example")
def get_example() -> JSONResponse:
    """提供可一键载入的重叠规则示例。"""
    return JSONResponse(EXAMPLE_PAYLOAD)


@app.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/api/analyze")
def post_analyze(req: DiffRequest) -> JSONResponse:
    try:
        result = analyze(req.old, req.new)
    except ValidationFailure as exc:
        # 输入无效：返回带位置的结构化错误，前端据此清除旧结果
        return JSONResponse(status_code=400,
                            content={"ok": False, "errors": exc.errors})
    return JSONResponse(content={"ok": True, "result": result})


# --------------------------------------------------------------------------- #
# TCP 网关管理 API
# --------------------------------------------------------------------------- #
def _gateway_response(extra: dict[str, Any] | None = None,
                      status_code: int = 200) -> JSONResponse:
    payload = GATEWAY.snapshot()
    if extra:
        payload.update(extra)
    return JSONResponse(status_code=status_code, content=payload)


async def _read_rules_payload(request: Request) -> Any:
    raw = await request.body()
    if raw is None or not raw.strip():
        raise ValidationFailure([{
            "sheet": "gateway", "field": None,
            "message": "请求体为空：请提交规则数组或 {\"rules\": [...]}",
        }])
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValidationFailure([{
            "sheet": "gateway", "field": None,
            "message": f"JSON 语法错误：{exc.msg}",
            "line": exc.lineno, "col": exc.colno,
        }]) from exc


async def _enable_rules(request: Request) -> JSONResponse:
    """校验并原子启用一组规则；任何错误都不改变活动规则与连接。"""
    try:
        payload = await _read_rules_payload(request)
        rules = parse_gateway_rules(payload)
    except ValidationFailure as exc:
        return JSONResponse(status_code=400, content={
            "ok": False,
            "errors": exc.errors,
            "message": "规则无效：活动规则与现有连接保持不变",
            "activeRules": [serialize_rule(r) for r in GATEWAY.active_rules()],
            "connectionCount": GATEWAY.snapshot()["connectionCount"],
        })

    switch = await GATEWAY.apply_rules(rules)
    return _gateway_response({"ok": True, "switch": switch})


@app.get("/api/gateway")
@app.get("/api/gateway/status")
def get_gateway_status() -> JSONResponse:
    """网关配置、活动规则、连接与统计。"""
    return _gateway_response()


@app.get("/api/gateway/config")
def get_gateway_config() -> JSONResponse:
    snap = GATEWAY.snapshot()
    return JSONResponse({"ok": True, "config": snap["config"],
                         "running": snap["running"]})


@app.get("/api/gateway/rules")
def get_gateway_rules() -> JSONResponse:
    snap = GATEWAY.snapshot()
    return JSONResponse({
        "ok": True,
        "activeRules": snap["activeRules"],
        "rules": snap["activeRules"],
        "ruleCount": snap["ruleCount"],
        "maxRules": MAX_RULES,
        "rulesEnabled": snap["rulesEnabled"],
        "rulesVersion": snap["rulesVersion"],
        "rulesUpdatedAt": snap["rulesUpdatedAt"],
    })


@app.post("/api/gateway/rules")
@app.put("/api/gateway/rules")
@app.post("/api/gateway/enable")
async def post_gateway_rules(request: Request) -> JSONResponse:
    """启用（原子切换）最多 20 条规则。

    请求体兼容：规则数组、JSON 文本、``{"rules": [...]}``、
    ``{"rules": "<JSON文本>"}``。成功返回时，被新规则拒绝的会话已经关闭且
    不会再转发任何数据；仍获准的会话保持不中断。
    """
    return await _enable_rules(request)


@app.delete("/api/gateway/rules")
@app.post("/api/gateway/rules/clear")
@app.post("/api/gateway/disable")
async def clear_gateway_rules() -> JSONResponse:
    """清空活动规则（回到默认拒绝，所有会话按新策略关闭）。"""
    switch = await GATEWAY.clear_rules()
    return _gateway_response({"ok": True, "switch": switch})


@app.get("/api/gateway/connections")
@app.get("/api/gateway/sessions")
def get_gateway_connections() -> JSONResponse:
    snap = GATEWAY.snapshot()
    return JSONResponse({
        "ok": True,
        "connections": snap["connections"],
        "sessions": snap["connections"],
        "connectionCount": snap["connectionCount"],
        "stats": snap["stats"],
    })


@app.delete("/api/gateway/connections/{session_id}")
@app.post("/api/gateway/connections/{session_id}/close")
async def close_gateway_connection(session_id: int) -> JSONResponse:
    closed = await GATEWAY.close_session(session_id)
    if not closed:
        return JSONResponse(status_code=404, content={
            "ok": False, "message": f"连接 {session_id} 不存在或已结束"})
    return _gateway_response({"ok": True, "closedSessionId": session_id})


@app.get("/api/gateway/example")
def get_gateway_example() -> JSONResponse:
    """返回一条可直接启用的示例规则（放行全部客户端到固定上游端口）。"""
    snapshot = GATEWAY.snapshot()
    example = [{
        "id": "demo-allow-all",
        "source": "0.0.0.0/0",
        "destination": "0.0.0.0/0",
        "portRange": [snapshot["upstreamPort"], snapshot["upstreamPort"]],
        "action": "allow",
    }]
    return JSONResponse({"ok": True, "rules": example, "example": example})


# --------------------------------------------------------------------------- #
@app.exception_handler(Exception)
def unhandled(_request, exc: Exception) -> JSONResponse:  # pragma: no cover
    return JSONResponse(status_code=500,
                        content={"ok": False, "errors": [
                            {"sheet": None, "field": None,
                             "message": f"服务器内部错误：{type(exc).__name__}: {exc}"}]})
