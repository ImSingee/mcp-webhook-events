# mcp-webhook-events

把 Webhook 变成 **MCP Events** 的平台。AI Agent 通过 MCP 自助创建 webhook URL，任何系统往这个 URL 发请求，Agent 都会以 MCP 事件的形式收到。

- 事件协议只实现 MCP Events 草案 [SEP-3415](docs/spec/sep-3415-events-extension.md)（扩展名 `io.modelcontextprotocol/events`），三种投递模式全部支持：
  - **push**：`events/stream`，SSE 长连接；
  - **poll**：`events/poll`；
  - **webhook**：`events/subscribe`，按 Standard Webhooks 签名回调。
- MCP 主路径是无状态的 2026-07-28 协议（`server/discover`、tools、events）。2025-06-18 和 2025-11-25 的旧客户端通过 `initialize` 使用 tools 和 `ping`，但拿不到 events，因为扩展只定义在 2026-07-28 上。
- 内置 OAuth 2.1 授权服务器：动态注册（DCR）、强制 PKCE S256、RFC 8707 resource 校验、回调带 `iss`、refresh token 轮换（重放时撤销整个授权）。
- 平台是单用户的：一个管理员密码，下面可以有多个 **Identity**（每个 Agent 一个）。授权时在 consent 页上选择或新建 Identity，token 绑定到这个 Identity。
- 两个二进制：
  - `mwe-server`：服务端加 Web 管理界面；
  - `mwe`：CLI，负责登录、管理、调试，并提供 stdio bridge。

设计见 [docs/plan.md](docs/plan.md)，管理 API 契约见 [docs/admin-api.md](docs/admin-api.md)，规范原文与摘录在 [docs/spec/](docs/spec/)。

## 部署

### Docker

```sh
docker build -t mcp-webhook-events .
docker run -d --name mwe -p 8080:8080 -v mwe-data:/data \
  -e MWE_PASSWORD='a-long-random-password' \
  -e MWE_PUBLIC_URL='https://events.example.com' \
  -e MWE_TRUST_PROXY=true \
  mcp-webhook-events
```

镜像说明：
- 以 nonroot 用户（uid 65532）运行；
- 数据库位于 `/data/mwe.db`，请挂卷持久化；
- 自带 `mwe-server healthcheck` 健康检查，请求 `/healthz`。

### 二进制

```sh
make build                       # 产出 bin/mwe-server 和 bin/mwe（CGO_ENABLED=0，纯 Go SQLite）
MWE_PASSWORD=... MWE_PUBLIC_URL=https://events.example.com bin/mwe-server
```

### 反向代理

公网部署时必须走 HTTPS（`MWE_PUBLIC_URL` 只允许 localhost 用 http）。用 nginx、Caddy 等反代时要注意：
- 设置 `MWE_TRUST_PROXY=true`，让登录失败退避按真实客户端 IP 计算；
- 对 `/mcp` 和 `/api/events/stream` 关闭响应缓冲：服务端已发送 `X-Accel-Buffering: no`，nginx 默认会遵守；
- 把读超时调到 60 秒以上：事件流每 20 秒发一次心跳，代理不应该提前断开；
- 平台必须挂在域名根路径下：OAuth 元数据和 `/mcp` 都在固定路径上，`MWE_PUBLIC_URL` 不能带 path。

### 环境变量

| 变量 | 默认值 | 说明 |
|---|---|---|
| `MWE_PASSWORD` | **必填** | 管理员密码，用于 Web 界面登录和 OAuth consent |
| `MWE_PUBLIC_URL` | **必填** | 对外 origin，不能带 path。OAuth issuer 用它，MCP resource（`<url>/mcp`）和 webhook URL 也都由它生成。除 localhost 外必须是 https |
| `MWE_ADDR` | `:8080` | 监听地址 |
| `MWE_DATA_DIR` | `./data` | 存放 `mwe.db` 的目录（镜像里是 `/data`） |
| `MWE_EVENT_RETENTION` | `168h` | 事件保留时长。超出保留期的 cursor 续传时会得到 `truncated: true` |
| `MWE_MAX_BODY_BYTES` | `262144` | webhook 请求体上限（256 KiB），超出返回 413 |
| `MWE_TRUST_PROXY` | `false` | 信任 `X-Forwarded-For` |
| `MWE_ALLOW_PRIVATE_CALLBACKS` | `false` | **仅限开发**。允许 webhook 投递模式回调 http 地址和内网、回环地址 |
| `MWE_CALLBACK_ALLOWLIST` | 空 | 逗号分隔的回调 origin（如 `https://hooks.example.com`）。列表内的 URL 视为已由运维确认，订阅时免验证握手（SEP-3415 端点确认方式 2）。https 规则和每次连接时的 SSRF 校验照常生效 |
| `MWE_LOG_LEVEL` | `info` | `debug` / `info` / `warn` / `error` |

示例见 [.env.example](.env.example)。

## 使用流程

1. 打开 `MWE_PUBLIC_URL`，用密码登录管理界面。界面里可以管理 Identity、webhook、channel、已授权客户端和订阅，查看实时事件，也可以发「平台广播」。
2. 让 Agent 接入 MCP（见下一节）。授权时在浏览器里选择或新建一个 Identity。
3. Agent 用 `webhook_create` 创建 webhook，拿到 URL 和 key（key 只显示这一次）。
4. 外部系统往这个 URL 发请求，key 有三种传法，任选一种：
   ```sh
   curl -X POST "$URL" -H "X-Webhook-Key: $KEY" -H 'Content-Type: application/json' -d '{"hello":"world"}'
   curl -X POST "$URL" -H "Authorization: Bearer $KEY" -d 'plain text'
   curl -X POST "$URL?key=$KEY" --data-binary @payload.bin
   ```
   成功返回 `202 {"event_id":"evt_…"}`。各种失败的返回码：
   - key 缺失或错误：401；
   - URL 不存在：404；
   - 请求体过大：413。
5. Agent 用 `channel_create` 建一个 channel（过滤规则），然后订阅事件 `webhook.received`，参数为 `{"channel": "<name>"}`。

### Channel 过滤

| mode | 含义 |
|---|---|
| `all` | 该 Identity 的所有 webhook 事件 |
| `include` | 只放行 `identifiers` 里列出的 identifier |
| `exclude` | 放行 `identifiers` 以外的 identifier |

补充规则：
- 名单里可以写保留 identifier，即以 `:` 开头的，例如 `:system`；
- channel 修改后立即对在线订阅生效，下一条事件就按新规则过滤；
- channel 删除后，在线订阅会收到 terminated（`-32023`）；
- **平台广播**（identity 为空，identifier 以 `:` 开头）不经过 channel 过滤，所有订阅都会收到。

## Agent 接入方式

MCP 地址是 `<MWE_PUBLIC_URL>/mcp`，只支持 OAuth 登录。

### 支持远程 MCP 和 OAuth 的客户端

直接把 `https://events.example.com/mcp` 填给客户端即可：
1. 客户端收到 401，从 `WWW-Authenticate` 找到 `/.well-known/oauth-protected-resource/mcp`；
2. 通过 DCR 注册自己；
3. 打开浏览器进入 consent 页。

注意：
- 要使用 events，客户端必须支持 2026-07-28 协议和 SEP-3415；
- 只支持旧协议的客户端只能使用 tools。

### 只支持 stdio 的客户端：`mwe mcp` bridge

```sh
mwe login https://events.example.com            # 浏览器里完成授权，选择 Identity
```

然后在客户端的 MCP 配置里加一个 stdio server：

```json
{ "mcpServers": { "webhook-events": { "command": "mwe", "args": ["mcp"] } } }
```

bridge 的行为：
- 每条 JSON-RPC 请求单独 POST 到服务端，并发执行；
- 自动带上 bearer token，必要时刷新；
- 自动补 `MCP-Protocol-Version`、`Mcp-Method`、`Mcp-Name` 这几个 header；
- 把 JSON 响应和 SSE 帧逐行写回 stdout；
- 长连接的 `events/stream` 不会阻塞其他请求；
- 收到 `notifications/cancelled` 时中止对应的 HTTP 请求；
- 401 时刷新一次 token，仍然失败就返回 JSON-RPC 错误，提示执行 `mwe login`。

### 已知客户端情况

- **Mastra `@mastra/mcp` ≥ 2.5**：支持 push、poll 和 webhook，但它在 `events/*` 请求上**不发送 `Mcp-Name` header**。SEP-3415 规定客户端 MUST 发送这个 header，缺失时服务端以 `400` + `-32020` 拒绝。本服务端按规范严格执行，所以接入时需要用自定义 `fetch` 补上这个 header，示例见下文「第三方客户端互通」。
- **ChatGPT**：只支持 webhook 模式，读取的是顶层 `capabilities.events`。服务端在 `server/discover` 里同时声明了它和 `capabilities.extensions["io.modelcontextprotocol/events"]`。

## MCP 能力

### Tools

所有 tools 的作用域都是 token 绑定的 Identity。每个 tool 都有 `inputSchema` 和 `outputSchema`，返回 `structuredContent` 和文本。

| Tool | 参数 | 说明 |
|---|---|---|
| `whoami` | – | 当前 Identity、客户端和 MCP 地址 |
| `webhook_create` | `identifier`, `name?`, `description?` | 返回 `url`、`key`（只此一次）和 `usage` |
| `webhook_list` | – | 列出 webhook（不含 key） |
| `webhook_update` | `identifier`, `name?`, `description?` | identifier 不可修改 |
| `webhook_rotate_key` | `identifier` | 生成新 key，旧 key 立即失效 |
| `webhook_delete` | `identifier` | 删除 webhook |
| `channel_create` | `name`, `mode`, `identifiers?`, `description?` | 创建过滤规则 |
| `channel_update` | `name`, `mode?`, `identifiers?`, `description?` | 部分更新，立即生效 |
| `channel_list` | – | 列出 channel |
| `channel_delete` | `name` | 在线订阅会收到 terminated |

identifier 和 channel 名的规则都是 `^[a-z0-9]+(-[a-z0-9]+)*$`，最多 64 个字符。

### Events（SEP-3415）

`server/discover` 返回的 capabilities：

```json
{
  "tools": {"listChanged": false},
  "extensions": {"io.modelcontextprotocol/events": {}},
  "events": {"listChanged": false}
}
```

只有一个事件类型 `webhook.received`：
- `delivery`：`["poll", "push", "webhook"]`；
- `inputSchema`：`{"channel": string}`（必填）。

| 方法 | 要点 |
|---|---|
| `events/list` | 单页 |
| `events/poll` | `cursor: null` 表示从现在开始；`maxEvents` 默认 100、上限 500；返回 `hasMore`、`nextPollMs`（5000） |
| `events/stream` | 依次推送 `notifications/events/active` → 回放（cursor 之后的事件）→ 实时事件。每 20 秒发一次 `notifications/events/heartbeat`，带 cursor。服务端主动关闭时先发 `notifications/events/terminated`，再发最终 result |
| `events/subscribe` | webhook 投递模式，见下文 |
| `events/unsubscribe` | 按 `(name, arguments, delivery.url)` 定位订阅 |
| `subscriptions/listen` | 最小实现：ack 一个空过滤器（服务端不发 list_changed），之后只保持连接 |

cursor 是不透明字符串，内部编码了全局事件序号。cursor 落后于保留期、或者 `maxAgeMs` 的下限越过了 cursor 时：
- 服务端从能提供的最早位置开始；
- 返回 `truncated: true`。

错误码按 SEP-3415：

| 错误 | 码 |
|---|---|
| 未知事件名或 channel | `-32023` NotFound |
| 授权被撤销 | `-32024` Forbidden |
| 订阅数超限 | `-32025` ResourceExhausted |
| 不支持的投递模式 | `-32026` Unsupported |
| 回调端点验证失败 | `-32027` CallbackEndpointError |
| 参数错误 | `-32602` |

请求校验遵循 2026-07-28 规范：
- `Origin` 必须为空或等于 `MWE_PUBLIC_URL`；本机部署（public URL 为回环地址）时也接受回环 Origin，并要求 `Host` 是回环地址（防 DNS rebinding），否则返回 403；
- `MCP-Protocol-Version`、`Mcp-Method`、`Mcp-Name` 缺失或与 body 不一致：`400` + `-32020`；
- `_meta` 缺少必填字段：`400` + `-32602`；
- 协议版本不支持：`400` + `-32022`；
- 方法不存在：`404` + `-32601`。2026-07-28 删除了 `ping`，所以 modern 请求中的 `ping` 也按未知方法返回这个错误；只有 legacy（2025-06-18 / 2025-11-25）路径仍回应 `ping`。

### Webhook 投递模式（`events/subscribe`）

```json
{"name": "webhook.received", "arguments": {"channel": "ci"},
 "delivery": {"mode": "webhook", "url": "https://receiver.example/hook", "secret": "whsec_<base64 24–64 字节>"},
 "cursor": null, "ttlMs": 3600000}
```

**订阅标识与生命周期**
- 订阅 key 是 `(identity, url, name, arguments)`，返回的 `id` 由 key 确定性推导而来。
- 用同一组参数再次 subscribe 就是续期，返回中会带 `deliveryStatus`。如果换了新 secret，旧 secret 会在 10 分钟内与新 secret 双签。
- TTL 默认 24 小时，最短 1 分钟，最长 7 天。`ttlMs: null` 也会给一个有限的 TTL。

**端点验证**
- 首次订阅某个 URL 时，服务端同步 POST 一个 `{"type":"verification","challenge":"…"}`，端点必须在 2xx 响应里回显 `{"challenge":"…"}`。
- 验证失败返回 `-32027`，`data.reason` 为 `challenge_failed`、`connection_refused` 等固定分类，不会包含端点的原始响应。
- 同一 Identity 对同一 URL 的验证结果缓存 24 小时；`MWE_CALLBACK_ALLOWLIST` 里的 origin 不需要握手。

**投递**
- 每个订阅按顺序逐条投递，带以下 header：
  - `webhook-id`
  - `webhook-timestamp`
  - `webhook-signature`：`v1,` + base64(HMAC-SHA256(secret, `id.timestamp.body`))
  - `X-MCP-Subscription-Id`
- 可以直接用任意 Standard Webhooks 库验签。
- 失败时按 5 秒、30 秒、2 分钟、10 分钟重试（共 5 次），每次重试都重新生成 timestamp 和签名。410 和 413 不重试。
- 订阅被终止时，服务端 POST `{"type":"terminated","error":{…}}`。
- 已投递位置落后于保留期时，服务端 POST `{"type":"gap","cursor":"…"}`。

**SSRF 防护**
- 回调地址必须是 https。
- 订阅时先解析域名，如果只解析到非全局可路由地址就直接拒绝，不做任何连接。
- 每次连接时都会重新解析，并直连校验过的 IP，所以 DNS rebinding 无效。
- 不跟随重定向，不使用环境变量里的代理。

## 事件格式

每个事件是一个 SEP-3415 `EventOccurrence`：

```json
{
  "eventId": "evt_…",
  "name": "webhook.received",
  "timestamp": "2026-10-29T08:00:00.123Z",
  "cursor": "…",
  "data": {
    "identifier": "github-push",
    "kind": "webhook",
    "webhook": {"name": "GitHub push"},
    "received_at": "2026-10-29T08:00:00.123Z",
    "request": {
      "method": "POST",
      "query": {"ref": ["main"]},
      "headers": {"Content-Type": ["application/json"], "X-Github-Event": ["push"]},
      "content_type": "application/json",
      "body_encoding": "json",
      "body": {"ref": "refs/heads/main"}
    },
    "message": null,
    "title": null
  }
}
```

- `cursor` 只在 push 和 webhook 模式下出现在事件上；poll 模式的 cursor 在响应顶层。
- `body_encoding` 的取值：
  - `json`：原样存放解析后的 JSON；
  - `text`：UTF-8 文本；
  - `base64`：二进制；
  - `none`：没有请求体。
- 不入库的内容：
  - header：`X-Webhook-Key`、`Authorization`、`Proxy-Authorization`、`Cookie`；
  - query：`key`。
- 平台广播的格式：`kind: "system"`，`identifier` 默认是 `:system`，`webhook` 和 `request` 为 `null`，正文放在 `message` 和 `title` 里。
- 事件内容来自第三方，是**不可信数据**。Agent 应当把它当作数据，不能当作指令。

## CLI `mwe`

```text
mwe login <server-url> [--profile p] [--no-browser]
mwe logout | status [--json]
mwe webhooks list | create <id> [--name] [--description] | update <id> | rotate-key <id> | delete <id>
mwe channels list | create <name> [--mode all|include|exclude] [--identifiers a,b] | update <name> ... | delete <name>
mwe events tail --channel c [--cursor x] [--max-age 10m] [--json]
mwe events poll --channel c [--cursor x] [--max-events n] [--follow] [--json]
mwe mcp [--profile p]
mwe version
```

- 凭据保存在 `~/.config/mwe/credentials.json`，权限 0600。可以用 `MWE_CONFIG_DIR` 或 `XDG_CONFIG_HOME` 改变位置。凭据按 profile 区分，`--profile` 或 `MWE_PROFILE` 选择 profile。
- 刷新 token 时持有文件锁，多个 `mwe` 进程同时运行不会重放同一个 refresh token。重放会被服务端视为泄露，进而撤销整个授权。
- 管理命令都是 MCP `tools/call` 的封装，和 Agent 走同一套 API。
- `events tail` 断线后用最后的 cursor 自动重连；退出时把最后的 cursor 打印到 stderr。

## 开发

```sh
make dev      # -tags dev：前端从 internal/web/assets 读盘，默认允许私网回调
make test     # go vet + go test -race ./...
make lint     # gofmt + vet（含 GOOS=linux）
make build
```

目录结构：

```
cmd/mwe-server, cmd/mwe
internal/config     环境变量
internal/store      SQLite（modernc，纯 Go）、迁移、各个 repo
internal/sqlitedb   打开 SQLite 的唯一入口（修复 modernc libc 环境变量问题）
internal/ident      identifier 规则
internal/events     channel 过滤、cursor、回放起点、hub
internal/core       各入口共享的业务操作（admin、tools、ingest）
internal/oauth      授权服务器和 bearer 校验
internal/mcp        手写的 JSON-RPC / Streamable HTTP（2026-07-28 加 legacy）、tools、events
internal/delivery   webhook 投递模式：订阅、验证握手、签名、重试、SSRF 防护
internal/ingest     webhook 接收端点
internal/admin      管理 API、consent API、页面路由
internal/web        嵌入式前端资源、ETag 和 ?v=hash
internal/mcpclient  CLI 侧的 OAuth 客户端和 MCP 客户端
internal/cli        子命令和 stdio bridge
internal/apptest    测试用：进程内启动完整服务并模拟各类客户端
```

### 第三方客户端互通（Mastra）

```js
import { MCPClient } from '@mastra/mcp';
const mcp = new MCPClient({ servers: { mwe: {
  url: new URL('https://events.example.com/mcp'),
  requestInit: { headers: { Authorization: `Bearer ${token}` } },
  protocolVersion: '2026-07-28',
  // Mastra 不在 events/* 上发 Mcp-Name（SEP-3415 要求必须发），用 fetch 补上
  fetch: async (url, init) => {
    const h = new Headers(init.headers); const m = JSON.parse(init.body ?? '{}');
    if (/^events\/(poll|stream|subscribe|unsubscribe)$/.test(m.method) && m.params?.name) h.set('mcp-name', m.params.name);
    return fetch(url, { ...init, headers: h });
  },
} } });
const sub = await mcp.events.subscribe('mwe', 'webhook.received', { channel: 'ci' }, { delivery: 'push' });
for await (const ev of sub) console.log(ev.data);
```

## 已知限制

- 不支持 OAuth Client ID Metadata Documents（CIMD）。2026-07-28 规范推荐 CIMD，DCR 已被标为 deprecated，但仍是 MAY。
- webhook 投递模式的端点确认只实现了「验证握手」和「服务端 allowlist」两种方式，没有实现 `/.well-known/mcp-webhook-receiver.json`，也不支持 `v1a` 非对称签名。
- `subscriptions/listen` 是最小实现：tools 列表是静态的，事件类型也是固定的，所以不发任何 list_changed。
- 订阅不会授予「永不过期」：`ttlMs: null` 也只给 7 天。
- SEP-3415 还是草案（Draft），错误码 `-32023`～`-32027` 是暂定编号，正式定稿时可能变化。
