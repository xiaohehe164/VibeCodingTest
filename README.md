# Banner 指纹识别系统

基于 Go 的批量 Banner 指纹识别系统。输入一批扫描原始数据（`ip`、`port`、`banner`），
输出协议、软件、版本、操作系统线索与置信度。项目采用 **client + server** 架构，
规则完全外置于 YAML，使用 **Docker Compose 一键启动**。

## 功能概览

- `server`：`POST /fingerprint` 批量识别，`GET /health` 健康检查。
- `client`：读取本地 JSON 文件，调用 server，以表格或 JSON 展示结果。
- 内置 57 条规则，覆盖 SSH、HTTP、MySQL/MariaDB、Redis、FTP，并扩展支持
  SMTP、POP3、IMAP、TLS、VNC、SMB、RDP、Telnet、Memcached、MQTT、RTSP、SIP。
- 未识别数据统一返回 `protocol: "unknown"`、`confidence: 0`，服务不会报错或崩溃。
- 兼容两种 banner 序列化形式：真实的二进制字节（如 JSON `\u0000`）以及导出文本中的
  字面转义（`\x00`、`\r\n`）。这意味着无论扫描器如何落盘，同一套规则都能工作。

## 快速开始

```bash
docker compose up --build
```

Compose 会完成以下动作：

1. 多阶段构建 server/client 两个镜像；
2. 启动 server，等待其内置健康探针通过；
3. client 通过内部网络 `http://server:8080` 调用识别接口，打印 `testdata/input.json`
   中全部数据的识别结果后退出；server 保持运行。

示例数据（题目自测数据 + 扩展数据）的 client 输出：

```text
IP        PORT   PROTOCOL   PRODUCT        VERSION  OS_HINT  CONFIDENCE
1.2.3.4   22     SSH        OpenSSH        8.9p1    Ubuntu   0.95
1.2.3.5   80     HTTP       nginx          1.24.0   -        0.90
1.2.3.6   443    HTTP       Apache         2.4.57   -        0.90
1.2.3.7   3306   MySQL      MySQL          8.0.32   -        0.90
1.2.3.8   6379   Redis      Redis          -        -        0.70
1.2.3.9   21     FTP        ProFTPD        1.3.7    -        0.90
1.2.3.10  8080   HTTP       Jetty          9.4.51   -        0.85
...
1.2.3.23  12345  unknown    -              -        -        0.00

Total: 31   Identified: 29   Unknown: 2
```

> client 是一次性任务（`restart: "no"`）。后台启动时查看结果：
> `docker compose up -d --build && docker compose logs -f client`

### 用自己的数据运行

替换 `testdata/input.json`，或把任意本地文件挂载进 client：

```bash
docker compose run --rm \
  -v "$PWD/my-input.json:/data/input.json:ro" \
  client
```

输出 JSON 而不是表格：

```bash
docker compose run --rm -e OUTPUT_FORMAT=json client
```

直接调用 API：

```bash
curl -s http://127.0.0.1:8080/health

curl -s -X POST http://127.0.0.1:8080/fingerprint \
  -H 'Content-Type: application/json' \
  --data @testdata/input.json
```

默认只把 API 发布到宿主机回环地址（`127.0.0.1:8080`）。确需对外暴露时：

```bash
BANNER_FINGERPRINT_BIND=0.0.0.0 docker compose up --build
```

## API

### `GET /health`

```json
{
  "status": "ok",
  "service": "banner-fingerprint",
  "version": "1.0.0",
  "rules": 57,
  "rule_files": 7,
  "uptime_seconds": 12
}
```

- 规则集为空时返回 HTTP 503 与 `status: "degraded"`。
- Docker 的 `HEALTHCHECK` 使用的正是该接口；`client` 通过
  `depends_on.condition: service_healthy` 等待其通过。

### `POST /fingerprint`

请求体为扫描记录数组（也兼容 `{"items": [...]}` 包装）：

```json
[
  {"ip": "1.2.3.4", "port": 22, "banner": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3"},
  {"ip": "1.2.3.5", "port": 80, "banner": "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0"}
]
```

响应与输入顺序一一对应：

```json
[
  {
    "ip": "1.2.3.4",
    "port": 22,
    "protocol": "SSH",
    "product": "OpenSSH",
    "version": "8.9p1",
    "os_hint": "Ubuntu",
    "confidence": 0.95
  }
]
```

| 字段 | 说明 |
| --- | --- |
| `ip` / `port` | 原样回显输入，不做改写 |
| `protocol` | 协议名；无法识别时为 `"unknown"` |
| `product` | 软件/产品名，可为空 |
| `version` | 版本号，可为空 |
| `os_hint` | 操作系统线索，可为空 |
| `confidence` | 0~1，规则匹配置信度；unknown 为 0 |

错误响应统一为：

```json
{"error": {"code": "invalid_json", "message": "..."}}
```

约束与错误码：

- 请求体上限 `MAX_BODY_BYTES`（默认 16 MiB），超限返回 `413 payload_too_large`。
- 单批记录数上限 `MAX_BATCH_SIZE`（默认 10000），超限返回 `400 batch_too_large`。
- 非法 JSON 返回 `400 invalid_json`；非法方法返回 `405`。
- 单条记录内容异常（空 banner、控制字符等）不会导致整批失败，只会落到 `unknown`。

## 识别规则：与代码解耦

所有识别知识位于 `rules/*.yaml`，**新增或修改规则不需要改动 Go 代码，也不需要重建镜像**：

- 镜像内置一份规则到 `/app/rules`；
- Compose 再把宿主机 `./rules` 以只读方式挂载到同一路径；
- 修改规则后向 server 发送 `SIGHUP` 热加载：

```bash
docker compose kill -s HUP server
```

加载是原子的：新规则集全部校验通过才会发布；任何一条规则非法，reload 失败，
**旧规则集继续生效**，server 不会被拖垮。启动时若规则集为空或非法，server 直接
fail-fast，避免“健康但永远识别为 unknown”。

### 规则格式

```yaml
rules:
  - id: http-nginx              # 全局唯一
    description: nginx 识别规则
    protocol: HTTP
    product: nginx
    version: '${version}'       # ${name} 引用正则命名捕获
    os_hint: '${os}'
    confidence: 0.9             # (0, 1]
    priority: 200               # 越大越先匹配
    match:                      # 所有条件 AND
      - type: regex
        field: banner           # banner（默认）或 ip
        pattern: '(?i)(?:^|[\r\n]|\\[rn])Server:\s*nginx/(?P<version>[0-9][0-9A-Za-z._+-]*)(?:\s*\((?P<os>[^)\r\n]+)\))?'
```

条件类型：

| type | 说明 |
| --- | --- |
| `regex` | Go RE2 正则；命名捕获供模板使用 |
| `contains` | 子串匹配，可配 `ignore_case: true` |
| `prefix` | 前缀匹配，可配 `ignore_case: true` |
| `port_in` | 端口白名单：`ports: [6379, 6380]` |

每个条件都支持 `negate: true`。匹配流程：

1. banner 会生成若干等价视图（原始值、字面转义解码后、去除外围空白），规则依次匹配；
2. 规则按 `priority` 降序、`confidence` 降序排序，首个命中的规则获胜；
3. 用命名捕获渲染 `product/version/os_hint` 模板，输出字段会裁剪控制字符并限制长度；
4. 无任何规则命中时输出 `unknown`。

规则文件在加载时进行严格校验（未知字段、重复 ID、非法正则、confidence 越界都会报错），
并配有单元测试：

```bash
go test ./...
```

## 生产级设计说明

### 1. 容器间访问收敛

- `client` 只加入内部网络 `backend`（`internal: true`，无出网路由），
  通过 Compose 服务名 `http://server:8080` 访问 server，不依赖宿主机端口或 IP。
- server 同时加入 `edge` 与 `backend`；API 端口默认只发布到宿主机 `127.0.0.1`，
  需显式设置 `BANNER_FINGERPRINT_BIND=0.0.0.0` 才对宿主机网卡开放。
- 不暴露数据库、不使用 host 网络、不挂载 Docker socket。

### 2. 真实启动依赖健康检测

- server 镜像内置静态 `healthcheck` 二进制（scratch 镜像没有 shell/curl/wget），
  实际请求 `GET /health` 并校验 `"status":"ok"` 与 HTTP 200。
- Compose 定义 `healthcheck`，client 使用 `depends_on.condition: service_healthy` 启动，
  而不是简单的容器“已启动”判断。
- `/health` 反映规则加载状态，规则集为空时返回 503。

### 3. 镜像编译与打包

- 多阶段构建：`golang:1.24-alpine` 编译，运行镜像为 `scratch`。
- `CGO_ENABLED=0` 生成静态二进制；`-trimpath -buildvcs=false` 去除本机路径信息；
  `-ldflags "-s -w"` 去符号表，版本号通过 `-X` 注入。
- 依赖下载与源码复制分层，命中 Docker 构建缓存。
- 构建上下文通过 `.dockerignore` 排除 `.git`、`.idea`、测试数据与文档。

### 4. 容器权限收紧

server 与 client 均启用：

- `user: "65532:65532"`（非 root，无登录 shell）；
- `read_only: true`（根文件系统只读）；
- `cap_drop: [ALL]`；
- `security_opt: [no-new-privileges:true]`；
- `pids_limit`、`mem_limit`、`cpus` 资源约束；
- 日志轮转（`max-size` / `max-file`）；
- server 额外使用 `tmpfs /tmp`，规则目录只读挂载。

### 5. 服务可靠性

- HTTP server 设置读头/读/写/空闲超时与头部大小限制。
- 请求体、批量大小均有上限；异常输入逐条降级为 `unknown`。
- panic 恢复中间件保证单个请求不会拖垮进程。
- 结构化 JSON 日志（`slog`），每个请求带 `X-Request-ID`。
- SIGINT/SIGTERM 优雅退出；SIGHUP 原子热加载规则。

## 项目结构

```text
.
├── cmd/
│   ├── server/          # HTTP API 服务
│   ├── client/          # 批量识别 CLI
│   └── healthcheck/     # scratch 镜像用静态健康探针
├── internal/
│   ├── api/             # 路由、中间件、请求解析
│   ├── fingerprint/     # 规则加载、匹配引擎、转义归一化
│   ├── model/           # 输入/输出数据模型
│   └── version/         # 构建版本
├── rules/               # 外置识别规则（7 个文件，57 条规则）
├── testdata/input.json  # 示例扫描数据
├── Dockerfile           # 多阶段构建（build / server / client 三个 target）
├── docker-compose.yml   # 生产级编排
└── README.md
```

## 本地开发（不使用 Docker）

```bash
# 启动 server（默认读取 RULES_DIR，监听 :8080）
RULES_DIR=./rules go run ./cmd/server

# 另开终端运行 client
go run ./cmd/client -server http://localhost:8080 -input testdata/input.json

# JSON 输出
go run ./cmd/client -server http://localhost:8080 -input testdata/input.json -format json

# 全部测试
go test ./...
```

### 环境变量

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `LISTEN_ADDR` | `:8080` | server 监听地址 |
| `RULES_DIR` | `/app/rules` | 规则目录 |
| `MAX_BATCH_SIZE` | `10000` | 单批最大记录数 |
| `MAX_BODY_BYTES` | `16777216` | 请求体上限 |
| `LOG_LEVEL` | `info` | `debug` / `info` / `warn` / `error` |
| `SERVER_URL` | `http://localhost:8080` | client 默认服务地址 |
| `INPUT_FILE` | `testdata/input.json` | client 默认输入文件 |
| `OUTPUT_FORMAT` | `table` | client 输出格式（`table` / `json`） |
| `HEALTH_URL` | `http://127.0.0.1:8080/health` | 健康探针地址 |

> 修改 `LISTEN_ADDR` 时，请同步设置 `HEALTH_URL`，否则 Docker 健康检查会失败。

## 已知边界

- 系统只做“基于给定 banner 的识别”，不会主动发起网络扫描或建立连接。
- 置信度是规则级先验值，用于结果排序与人工复核优先级，不是统计意义上的概率。
- API 不内置 TLS 与鉴权；生产部署建议置于反向代理/API 网关之后，并限制来源网络。
- 规则优先级决定冲突时的胜出者；新增通用规则时应使用较低 `priority`。
