# 防火墙规则差分台 · TCP 访问网关

同一个单进程 Web 应用提供两项能力：

1. **规则变更差分台**：上线前精确比对两份有序 IPv4/TCP 规则集，列出规则变更会
   **新增放行**与**新增阻断**的全部流量区域（边界切分、精确枚举，不抽样）。
2. **TCP 访问网关**：按同一套规则语义实时放行/拒绝 TCP 连接；管理员在浏览器
   编辑并启用规则后，**失去权限的已建立长连接立即被断开**，仍获准的连接不中断。

浏览器入口：

* `http://127.0.0.1:8000/`：规则差分台（首页，含网关导航入口）
* `http://127.0.0.1:8000/gateway`：TCP 访问网关管理页

## 规则语义

* 仅支持 **IPv4 + TCP**；
* 每条规则：`id`（同一份规则集内唯一的整数或字符串）、`source`/`destination`
  （严格 IPv4 CIDR，主机位为 0；全网 `0.0.0.0/0`，单机 `a.b.c.d/32`）、
  `portRange`（目的端口闭区间 `[下界, 上界]`，0–65535 整数）、
  `action`（小写 `allow` / `deny`）；
* 按数组顺序匹配，**首条命中生效**；全部未命中即**默认拒绝**（DEFAULT DENY）；
* 每份规则集最多 **20 条**。

```json
[
  {
    "id": 1,
    "source": "10.0.0.0/8",
    "destination": "172.16.0.0/12",
    "portRange": [80, 443],
    "action": "allow"
  }
]
```

## TCP 访问网关

### 启动配置固定上游

上游 **IPv4 地址与端口由启动配置固定**，运行期间不可由请求改动：

| 环境变量 | 别名 | 默认值 | 说明 |
|---|---|---|---|
| `GATEWAY_UPSTREAM_HOST` | `GATEWAY_UPSTREAM_IP` / `GATEWAY_UPSTREAM_ADDR` / `UPSTREAM_HOST` / `UPSTREAM_IP` / `UPSTREAM_ADDR` | `127.0.0.1` | 上游 IPv4 地址；主机名会在启动时解析并固定为 IPv4 |
| `GATEWAY_UPSTREAM_PORT` | `UPSTREAM_PORT` | `9000` | 上游目的端口 |
| `GATEWAY_LISTEN_HOST` | `GATEWAY_LISTEN_ADDR` / `GATEWAY_BIND_HOST` / `GATEWAY_HOST` | `127.0.0.1` | 网关 TCP 监听地址（容器内用 `0.0.0.0`） |
| `GATEWAY_LISTEN_PORT` | `GATEWAY_BIND_PORT` / `GATEWAY_TCP_PORT` / `GATEWAY_PORT` | `9001` | 网关 TCP 监听端口 |
| `GATEWAY_CONNECT_TIMEOUT` | — | `5` | 连接上游超时（秒） |

### 判定与连接行为

* **判定维度**：实际 TCP 对端源 IP（由内核 `peername` 提供）∈ `source`，
  启动配置固定的上游 IPv4 地址 ∈ `destination`，固定上游端口 ∈ `portRange`；
  **绝不采信客户端在报文里自报的地址**；
* **启动时活动规则为空**：所有新连接按默认拒绝立即关闭；
* **双向透传**：获准连接在客户端与上游之间原样搬运字节，不做任何改写；
* **单向 EOF**：任一方向读到 EOF 时只对该方向的目标执行 `write_eof`（半关闭），
  反方向继续接收/转发，直到两个方向都结束才释放会话；
* **上游连接失败**：关闭客户端一侧、清理会话并计入 `upstreamFailed`。

### 规则切换（撤权）语义

管理页的“启用规则”调用是**原子切换**：

* 新规则拒绝的**新建、已建立、正在连接上游**会话会被立即关闭；
* 切换协程会等待这些会话的转发任务真正终止后才返回，因此**接口成功返回后，
  被拒会话不会再向上游或客户端转发任何字节**；
* 新规则仍然放行的会话完全不中断，只更新其命中的规则编号；
* **非法规则不会改变任何状态**：接口返回 400，活动规则与现有连接保持不变
  （校验在切换前完成）；
* 清空规则（`DELETE /api/gateway/rules`）等价于默认拒绝，会关闭所有会话。

### 单网关进程

网关是 FastAPI 应用内的进程内单例，由 lifespan 启动。必须只运行 **一个
uvicorn worker**（默认即为 1）：

* 不要使用 `--workers N`（N > 1）或 `--reload`；
* Compose 中只有一个 `access-gateway` 容器，不配置多副本；
* 监听失败不会导致 Web 管理页不可用，错误会显示在 `/api/gateway` 的
  `lastError` 字段和管理页状态卡中。

## 快速启动（Docker Compose）

```bash
docker compose up --build
# 浏览器打开 http://127.0.0.1:8000/gateway
# 也可靠 http://127.0.0.1:8000/ 进入首页
```

Compose 包含两个服务：

* `access-gateway`：Web 管理页 + 唯一的 TCP 网关进程（宿主机 `8000` / `9001`）；
* `tcp-echo`：本地临时服务（TCP 回显），仅在内网 `9000` 暴露给网关。

端口默认只绑定宿主机回环地址。需要对局域网开放时，把
`docker-compose.yml` 中的 `"127.0.0.1:8000:8000"` / `"127.0.0.1:9001:9001"`
改为 `"8000:8000"` / `"9001:9001"`。容器内置健康检查，访问 `/api/health` 探活。

### Docker 环境长连接撤权演示

1. 打开 `http://127.0.0.1:8000/gateway`，点“载入示例”，再点“启用规则”。
   Docker 网络中客户端源 IP 通常是桥接网段，示例使用 `0.0.0.0/0` 放行；
2. 建立长连接：

   ```bash
   nc 127.0.0.1 9001
   hello
   ```

   输入 `hello` 后应看到回显（网关 → `tcp-echo` → 网关 → 客户端）；
3. 回到管理页，把规则改为 `deny`（或直接点“清空规则”）并启用；
4. 在 `nc` 中再输入一行并回车，连接会立即关闭，后续数据不会再转发。

也可用脚本自动完成（脚本会先启用放行规则、收发数据、再切换拒绝规则并验证关闭）：

```bash
python3 scripts/demo_revoke.py
```

## 本地直接运行（无需 Docker）

终端 1，启动回显上游：

```bash
python -m app.echo_service --host 127.0.0.1 --port 9000
```

终端 2，启动 Web + TCP 网关：

```bash
pip install -r requirements.txt
GATEWAY_UPSTREAM_HOST=127.0.0.1 GATEWAY_UPSTREAM_PORT=9000 \
GATEWAY_LISTEN_HOST=127.0.0.1 GATEWAY_LISTEN_PORT=9001 \
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

本地回环演示时，客户端源 IP 为 `127.0.0.1`，可用
`source = "127.0.0.1/32"` 的精确规则。然后：

```bash
nc 127.0.0.1 9001          # 输入任意文本查看回显
python3 scripts/demo_revoke.py --api-base http://127.0.0.1:8000 \
    --gateway-host 127.0.0.1 --gateway-port 9001
```

## 管理页与 API

管理页 `/gateway` 提供：网关/上游/IP 状态卡、规则 JSON 编辑器、启用/清空/
重置按钮、活动规则表、每 2 秒自动刷新的连接表（客户端地址、上游地址、
`connecting`/`relaying` 状态、命中规则、双向字节数与持续时间）。

| 方法 | 路径 | 说明 |
|---|---|---|
| `GET` | `/api/gateway`、`/api/gateway/status` | 配置、活动规则、连接、统计 |
| `GET` | `/api/gateway/config` | 监听与固定上游配置 |
| `GET` | `/api/gateway/rules` | 活动规则（`activeRules` / `rules`） |
| `POST`/`PUT` | `/api/gateway/rules` | **启用规则**（原子切换，最多 20 条） |
| `POST` | `/api/gateway/enable` | 同上 |
| `DELETE` | `/api/gateway/rules` | 清空规则（回到默认拒绝） |
| `POST` | `/api/gateway/rules/clear`、`/api/gateway/disable` | 同上 |
| `GET` | `/api/gateway/connections`、`/api/gateway/sessions` | 当前连接 |
| `DELETE` | `/api/gateway/connections/{id}` | 管理员主动关闭某条连接 |
| `GET` | `/api/gateway/example` | 可直接启用的示例规则 |

`POST /api/gateway/rules` 的请求体兼容以下形式：

```jsonc
// 1) 规则数组
[{"id": 1, "source": "0.0.0.0/0", "destination": "0.0.0.0/0",
  "portRange": [9000, 9000], "action": "allow"}]

// 2) 对象包装
{"rules": [ ... ]}

// 3) 规则 JSON 文本（也接受 text/plain 请求体）
{"rules": "[ ... ]"}
```

成功响应包含 `activeRules`、`ruleCount`、`connections`、`stats`，以及本次切换的
`switch`：`ruleCount`、`closedSessionCount`、`closedSessionIds`、
`keptSessionCount`。

校验失败返回 HTTP 400：

```json
{
  "ok": false,
  "errors": [
    {"sheet": "gateway", "ruleIndex": 1, "field": "source",
     "message": "source 不是合法的 IPv4 CIDR：..."}
  ],
  "message": "规则无效：活动规则与现有连接保持不变",
  "activeRules": [ ... ],
  "connectionCount": 3
}
```

### 命令行示例

```bash
# 启用全放行（替换成你环境的上游端口）
curl -X POST http://127.0.0.1:8000/api/gateway/rules \
  -H 'Content-Type: application/json' \
  -d '[{"id":"allow","source":"0.0.0.0/0","destination":"0.0.0.0/0",
       "portRange":[9000,9000],"action":"allow"}]'

# 查看状态与连接
curl -s http://127.0.0.1:8000/api/gateway | python3 -m json.tool

# 清空规则（默认拒绝，关闭所有会话）
curl -X DELETE http://127.0.0.1:8000/api/gateway/rules
```

## 规则差分 API

* `GET /api/example`：返回可直接载入的重叠规则示例；
* `POST /api/analyze`：请求体 `{"old": "<旧规则JSON文本>", "new": "<新规则JSON文本>"}`；
  * 成功：`{"ok": true, "result": {...}}`；
  * 输入无效：HTTP 400，`{"ok": false, "errors": [...]}`，每条错误标明
    所属规则集（`sheet`）、第几条规则（`ruleIndex`）、字段（`field`），
    JSON 语法错误另附行列号（`line`/`col`）。前端收到错误会**清除旧结果**。

结果分「新增放行」「新增阻断」两组，每组由若干**互不重叠的三维长方体区域**组成：

* **源地址区间**、**目的地址区间**（闭区间；若恰好对齐一个 CIDR 会同时标注）、
  **目的端口区间**（闭区间）；
* **覆盖报文数** = 源地址数 × 目的地址数 × 端口数（以字符串返回，避免 32 位整数溢出）；
* **示例报文**：取三个区间的最小端点组成的具体 TCP 报文；
* **变更前 / 变更后判定**：分别给出命中规则编号、顺序与动作；未命中标记
  `defaultDeny: true`、`ruleId: "DEFAULT-DENY"`。

精确性原理与实现见 `app/engine.py`；`tests/` 中的穷举测试会在受限子空间内
逐点枚举（非抽样）核对输出区域，无遗漏、无重复。

## 目录结构

```
.
├── app/
│   ├── __init__.py
│   ├── engine.py          # 校验 + 边界切分 + 精确差分（核心，无第三方依赖）
│   ├── example_data.py    # 内置重叠规则示例
│   ├── gateway.py         # TCP 访问网关：规则判定、双向透传、原子切换
│   ├── echo_service.py    # 本地 TCP 回显上游
│   ├── main.py            # FastAPI 路由 + lifespan 启动单网关
│   └── static/
│       ├── index.html     # 规则差分首页（含网关入口）
│       └── gateway.html   # TCP 网关管理页
├── scripts/
│   └── demo_revoke.py     # 长连接撤权自动演示
├── tests/
│   ├── test_engine.py     # 校验、首条匹配语义、穷举精确性
│   ├── test_api.py        # 差分 API
│   ├── test_gateway.py    # 真实 socket：默认拒绝/透传/半关闭/撤权/连接中切换/上游失败
│   └── test_gateway_api.py# 网关管理 API 与页面入口
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
└── pytest.ini
```

## 运行测试

```bash
pip install -r requirements.txt pytest httpx
pytest
```
