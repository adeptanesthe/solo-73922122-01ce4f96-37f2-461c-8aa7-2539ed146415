"""网关管理 API 测试：规则启用、非法提交保留活动规则、页面入口。"""

from __future__ import annotations

import json
from ipaddress import IPv4Address

import pytest
from fastapi.testclient import TestClient

from app.gateway import GATEWAY, GatewayConfig
from app.main import app

client = TestClient(app)

VALID_RULE = {
    "id": 1,
    "source": "0.0.0.0/0",
    "destination": "0.0.0.0/0",
    "portRange": [9000, 9000],
    "action": "allow",
}


@pytest.fixture(autouse=True)
def reset_rules():
    client.delete("/api/gateway/rules")
    yield
    client.delete("/api/gateway/rules")


def test_lifespan_starts_single_gateway_with_empty_rules():
    """FastAPI lifespan 必须启动进程内唯一的网关，且启动时规则为空。"""
    original_config = GATEWAY.config
    GATEWAY.config = GatewayConfig(
        listen_host="127.0.0.1", listen_port=0,
        upstream_host="127.0.0.1", upstream_port=1,
        upstream_ip=IPv4Address("127.0.0.1"),
    )
    try:
        with TestClient(app) as managed:
            status = managed.get("/api/gateway").json()
            assert status["running"] is True
            assert status["activeRules"] == []
            assert status["ruleCount"] == 0
            assert status["connections"] == []
        # 退出 lifespan 后网关停止
        assert GATEWAY.running is False
    finally:
        GATEWAY.config = original_config


def test_home_page_links_to_gateway_management():
    resp = client.get("/")
    assert resp.status_code == 200
    assert "TCP 访问网关" in resp.text
    assert 'href="/gateway"' in resp.text

    page = client.get("/gateway")
    assert page.status_code == 200
    assert "text/html" in page.headers["content-type"]
    assert "TCP 访问网关管理" in page.text


def test_gateway_starts_with_empty_rules():
    resp = client.get("/api/gateway")
    assert resp.status_code == 200
    data = resp.json()
    assert data["activeRules"] == []
    assert data["ruleCount"] == 0
    assert data["maxRules"] == 20
    assert data["connections"] == []
    # 启动配置：上游地址与端口固定
    assert {"upstreamHost", "upstreamPort", "listenHost", "listenPort"} <= set(data)


def test_enable_rules_and_read_them_back():
    resp = client.post("/api/gateway/rules", json=[VALID_RULE])
    assert resp.status_code == 200
    data = resp.json()
    assert data["ok"] is True
    assert data["ruleCount"] == 1
    assert data["activeRules"][0]["id"] == 1
    assert data["activeRules"][0]["source"] == "0.0.0.0/0"
    assert data["switch"]["ruleCount"] == 1

    rules = client.get("/api/gateway/rules").json()
    assert rules["ok"] is True and rules["ruleCount"] == 1
    assert rules["rules"] == rules["activeRules"]


def test_invalid_rules_keep_active_rules_and_connections():
    good = {
        "id": "keep-me",
        "source": "0.0.0.0/0",
        "destination": "0.0.0.0/0",
        "portRange": [9000, 9000],
        "action": "allow",
    }
    assert client.post("/api/gateway/rules", json=[good]).status_code == 200
    assert client.get("/api/gateway").json()["ruleCount"] == 1

    bad = {
        "id": "bad",
        "source": "10.0.0.5/24",       # 主机位非 0
        "destination": "0.0.0.0/0",
        "portRange": [80],             # 区间元素不足
        "action": "maybe",             # 非法动作
    }
    resp = client.post("/api/gateway/rules", json=[bad])
    assert resp.status_code == 400
    data = resp.json()
    assert data["ok"] is False
    fields = {e.get("field") for e in data["errors"]}
    assert {"source", "portRange", "action"} <= fields
    assert data["activeRules"][0]["id"] == "keep-me"
    # 活动规则保持原样，连接列表也不受影响
    status = client.get("/api/gateway").json()
    assert status["ruleCount"] == 1
    assert status["activeRules"][0]["id"] == "keep-me"
    assert status["connectionCount"] == 0


def test_invalid_json_and_too_many_rules_rejected():
    too_many = [{"id": i, "source": "0.0.0.0/0",
                 "destination": "0.0.0.0/0",
                 "portRange": [9000, 9000], "action": "allow"}
                for i in range(21)]
    resp = client.post("/api/gateway/rules", json=too_many)
    assert resp.status_code == 400
    assert any("20" in e["message"] for e in resp.json()["errors"])

    resp = client.post("/api/gateway/rules", content=b"{not json")
    assert resp.status_code == 400
    assert "JSON" in resp.json()["errors"][0]["message"]


def test_rules_accept_object_and_json_text_forms():
    resp = client.post("/api/gateway/rules",
                       json={"rules": [VALID_RULE]})
    assert resp.status_code == 200
    assert resp.json()["ruleCount"] == 1

    resp = client.post("/api/gateway/rules",
                       json={"rules": json.dumps([VALID_RULE])})
    assert resp.status_code == 200
    assert resp.json()["ruleCount"] == 1

    resp = client.post("/api/gateway/rules",
                       content=json.dumps([VALID_RULE]).encode())
    assert resp.status_code == 200
    assert resp.json()["ruleCount"] == 1


def test_clear_rules_returns_to_default_deny():
    assert client.post("/api/gateway/rules", json=[VALID_RULE]).status_code == 200
    resp = client.delete("/api/gateway/rules")
    assert resp.status_code == 200
    assert resp.json()["ruleCount"] == 0
    assert resp.json()["rulesEnabled"] is False


def test_connections_and_example_endpoints():
    resp = client.get("/api/gateway/connections")
    assert resp.status_code == 200
    data = resp.json()
    assert data["ok"] is True and data["connections"] == []

    example = client.get("/api/gateway/example").json()
    assert example["ok"] is True
    assert len(example["rules"]) == 1
    assert example["rules"][0]["action"] == "allow"
    # 示例本身必须能被启用
    resp = client.post("/api/gateway/rules", json=example["rules"])
    assert resp.status_code == 200
