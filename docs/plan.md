# mcp-webhook-events：Webhook → MCP Events 平台（Server + CLI）

## Context

这个平台让 AI Agent 通过 MCP 自助注册 webhook，并把 webhook 收到的内容以 **MCP Events**（官方草案 SEP-3415，扩展名为 `io.modelcontextprotocol/events`）的形式推给 Agent。仓库目前是空的（`master` 分支还没有任何 commit）。

已确认的决策：
- 事件协议**只做 SEP-3415**，以 PR #3415 的 head `b08e4f9` 为准。实现前先把 SEP 原文拉到 `docs/spec/`，所有线上格式都以原文为准。
- CLI 有两个职责：一是 stdio bridge，二是管理/调试命令。
- channel 是**服务端持久化的实体**，可以随时修改，修改后对在线订阅立即生效。
- 平台是单用户的，密码由环境变量固定。MCP 只支持 OAuth 登录，客户端注册走 DCR；授权时可以选择或新建 Agent Identity。

调研得出的关键约束：
- SEP-3415 只能跑在 2026-07-28 协议上。这一版协议是无状态的：没有 initialize，没有 session，强制要求 `server/discover`，并要求请求带 `MCP-Protocol-Version`、`Mcp-Method`、`Mcp-Name` 这几个 header。
- 两个 Go SDK 都做不了 `events/stream`。go-sdk v1.8.0 不能发自定义通知；mcp-go v1.4.0 不能注册自定义请求方法。
- 所以 MCP 层**自己手写**，和 magpie `internal/gateway/hub_mcp.go` 的做法一样，用标准库实现无状态 JSON-RPC。这样 SEP 演进时我们能完全自己掌控。
- 实际能消费 SEP-3415 的客户端：
  - ChatGPT 只支持 webhook 模式，而且读的是顶层 `capabilities.events`。
  - Vercel AI SDK 只支持 webhook 模式。
  - Mastra `@mastra/mcp` ≥2.5 支持 push、poll 和 webhook。
  - Claude Code 不支持；Codex 只对托管应用开放。
  - 因此 **webhook 投递模式（`events/subscribe`）必须做**，server/discover 里也要同时声明 `extensions["io.modelcontextprotocol/events"]` 和顶层 `events`。

## 技术栈与结构

- Module 路径：`github.com/ImSingee/mcp-webhook-events`，Go 1.26。产物是两个二进制：`cmd/mwe-server` 和 `cmd/mwe`。
- 沿用 magpie 的模式：
  - 路由用标准库 `net/http.ServeMux`（Go 1.22 的方法匹配写法）。
  - 存储用 `modernc.org/sqlite`（纯 Go，不需要 CGO），并加上 magpie `internal/sqlitedb` 里那个 libc getenv shim。
  - 日志用 `log/slog`。
  - CLI 用手写的子命令 switch 加标准库 `flag`。
- UI 沿用 magpie `internal/gui` 的方式：
  - `//go:embed assets` 配合 `fs.Sub`，由 `http.FileServer` 提供静态文件，外面包一层 ETag 和 `?v=hash` 的版本化中间件。
  - `-tags dev` 时直接读磁盘上的文件。
  - 页面是原生 HTML/CSS/JS，没有构建步骤、没有 CDN；用 CSS 变量，深色主题同时支持 `prefers-color-scheme` 和 `data-theme`。
  - 遵守 magpie code-standards 里的 GUI 规则：不用原生 `<select>`，点击不触发页面滚动，不用彩色左边框。

```
cmd/mwe-server/main.go      cmd/mwe/main.go
internal/config      环境变量解析与校验
internal/store       sqlite、迁移、各 repo（identities/oauth/webhooks/channels/events/subscriptions）
internal/ident       identifier 规则：用户可定义的 ^[a-z0-9]+(-[a-z0-9]+)*$（≤64），保留的 ^:[a-z0-9][a-z0-9:-]*$
internal/oauth       授权服务器（metadata/register/authorize/token/revoke）+ bearer 校验
internal/admin       密码登录会话、admin JSON API、CSRF
internal/web         嵌入的 assets（index.html/app.css/app.js/login.html/consent.html）
internal/mcp         JSON-RPC 类型、HTTP transport（2026-07-28 + legacy）、tools、events 扩展
internal/events      hub（进程内 pub/sub）、cursor、channel 过滤、回放查询
internal/delivery    webhook 模式投递 worker、Standard Webhooks 签名、防 SSRF 的 dialer
internal/ingest      webhook 接收端点
internal/mcpclient   CLI 侧：OAuth 客户端（DCR+PKCE+loopback，参考 magpie internal/mcpauth）、2026-07-28 HTTP 客户端（含 SSE）
internal/cli         子命令与 stdio bridge
```

## Server 配置（环境变量）

| 变量 | 说明 |
|---|---|
| `MWE_PASSWORD` | **必填**，平台密码 |
| `MWE_PUBLIC_URL` | **必填**，对外地址。OAuth issuer、MCP resource（`<url>/mcp`）和 webhook URL 都由它生成。除 localhost 外必须是 https |
| `MWE_ADDR` | 默认 `:8080` |
| `MWE_DATA_DIR` | 默认 `./data`，存放 `mwe.db` |
| `MWE_EVENT_RETENTION` | 默认 `168h` |
| `MWE_MAX_BODY_BYTES` | 默认 `262144`，和 SEP 的 256 KiB 上限一致 |
| `MWE_TRUST_PROXY` | 信任 `X-Forwarded-*` |
| `MWE_ALLOW_PRIVATE_CALLBACKS` | 开发用，允许投递到 http/内网地址 |

## 数据模型（SQLite）

- **`identities`**：`id`、`name`（唯一）、`created_at`。
- **`oauth_clients`**：DCR 注册的客户端。`client_id`、可选的 `client_secret_hash`、`client_name`、`redirect_uris`、`token_endpoint_auth_method`。
- **`oauth_codes`**：授权码，存 hash，有效期 60 秒，一次性。同时记录 `client_id`、`identity_id`、`redirect_uri`、`code_challenge`、`resource`、`scope`。
- **`oauth_tokens`**：access token 存 hash，有效 1 小时；refresh token 存 hash，有效 90 天，每次使用都轮换，旧 token 被重放时撤销整个 family。另有 `identity_id`、`client_id`、`family_id`、`revoked_at`。**同一个 identity 可以有多个 client 或授权。**
- **`webhooks`**：
  - 基本字段：`id`、`identity_id`、`identifier`、`name`、`description`。
  - `path_token`：随机生成，URL 为 `/hooks/<path_token>`。
  - `key_hash`：key 只在创建或轮换时明文返回一次。
  - 唯一约束 `UNIQUE(identity_id, identifier)`。
- **`channels`**：`id`、`identity_id`、`name`（规则同 identifier，在 identity 内唯一）、`description`、`mode`（取 `all`/`include`/`exclude`）、`identifiers` JSON、`updated_at`。
- **`events`**：
  - `seq` 是全局自增主键，cursor 就是对 seq 的不透明编码。
  - `id` 形如 `evt_…`。
  - `identity_id` 为 NULL 表示平台广播。
  - `identifier` 可以是用户 identifier，也可以是 `:` 开头的保留 identifier。
  - 另有 `kind`（`webhook`/`system`）、`webhook_id`、`received_at`、`data` JSON。
- **`event_subscriptions`**：webhook 模式的订阅。`id`（`sub_…`）、`identity_id`、`client_id`、`name`、`channel_id`、`url`、`secret`、`cursor`、`expires_at`、`status`、`failure_count`。

## 核心行为

### Webhook 接收：`ANY /hooks/{path_token}`
- **key** 有三种传法，都可以：
  - header `X-Webhook-Key`
  - `Authorization: Bearer <key>`
  - query `?key=`
  比较 key 时用常量时间比较。错误响应：key 错误返回 401，token 不存在返回 404，body 超过上限返回 413。
- **入库**：key 相关的 header 和 query 不入库。body 按以下顺序处理：
  1. 能解析成 JSON 就以原始 JSON 存放；
  2. 否则是 UTF-8 文本就存字符串；
  3. 再否则存 base64。
- **响应**：成功返回 `202 {"eventId":"evt_…"}`。写库后发布到 hub。
- **event `data` 的形状**：
  - `identifier`、`kind`、`webhook{name}`、`receivedAt`
  - `request{method, query, headers, contentType, bodyEncoding, body}`

### Channel 过滤（`internal/events`）
- 匹配规则：`all` 匹配该 identity 的全部事件；`include` 只放行名单内的 identifier；`exclude` 放行名单以外的。名单里允许出现 `:` 开头的 identifier。
- **`identity_id IS NULL` 的平台广播不经过 channel 过滤，总是投递**（对应需求第 8 条）。server 的 `instructions` 和工具描述里要明确告诉 Agent：
  - 订阅范围外的事件可以直接忽略；
  - `:` 开头的 identifier 是平台保留的。
- channel 发生 update 或 delete 时通知 hub，在线 stream 下一条事件就按新规则过滤。channel 被删除时，向在线 stream 发 `notifications/events/terminated`（-32023）并关闭。
- 为了让第 7、8 条有真实的代码路径并能测试，Admin UI 提供「平台广播」：写入 identifier 为 `:system` 的广播事件。

### MCP 端点 `/mcp`（手写，`internal/mcp`）

**通用规则**
- 只接受 POST，GET 和 DELETE 返回 405。
- 校验 Origin。
- bearer 无效时返回 401，并带 `WWW-Authenticate: Bearer resource_metadata="…/.well-known/oauth-protected-resource/mcp"`。
- 校验 token 的 audience，必须等于 `<public>/mcp`。

**2026-07-28（主路径）**
- 校验 `_meta` 中的 protocolVersion 和 clientCapabilities，以及 `MCP-Protocol-Version`、`Mcp-Method`、`Mcp-Name` 三个 header。出错时按规范返回 -32020、-32022 或 -32601 和对应的 HTTP 状态码。
- 支持的方法：`server/discover`、`tools/list`、`tools/call`、`events/list|poll|stream|subscribe|unsubscribe`，以及 `subscriptions/listen` 的最小实现（具体以规范原文为准）。
- 2026-07-28 已删除 `ping`，modern 请求里的 `ping` 按未知方法返回 404 + -32601。
- 每个 result 都带 `resultType:"complete"`。

**legacy（2025-06-18、2025-11-25）**
- 只支持 `initialize`、`notifications/initialized`、`ping` 和 tools，不发 session id，也不暴露 events（扩展要求 2026-07-28）。
- 这样较老的客户端至少能管理 webhook 和 channel。

**Tools**（作用域是 token 绑定的 identity）
- `whoami`
- `webhook_create {identifier,name,description}` 返回 `{identifier,url,key,usage}`
- `webhook_list`、`webhook_update`、`webhook_rotate_key`、`webhook_delete`
- `channel_create {name,description?,mode,identifiers?}`
- `channel_update`（可部分更新）、`channel_list`、`channel_delete`
- 每个工具都有 inputSchema 和 outputSchema，返回 structuredContent 加文本。

**Events 扩展**：只有一个事件名 `webhook.received`。
- inputSchema 为 `{channel: string}`；payloadSchema 描述上面的 data 结构。
- `delivery` 取 `["poll","push","webhook"]`。

**`events/stream` 的流程**
1. 校验 channel；
2. 先订阅 hub，再查询回放区间（seq > cursor），按 seq 去重。cursor 为 null 表示从现在开始；cursor 比保留期还早时设 `truncated=true`；同时遵守 `maxAgeMs`。
3. 依次发出 SSE：先 `notifications/events/active`，然后是回放的 `event`，再进入实时的 `event`，期间每 20 秒发一次 `heartbeat`。
4. 客户端断开就结束；server 主动关闭时发最终 result。

**`events/poll`**：`maxEvents` 默认 100、上限 500，返回 `hasMore` 和 `nextPollMs`。

**`events/subscribe`（webhook 模式）**
- `secret` 必须是 `whsec_` 格式；持久化订阅，返回 `refreshBefore`。用同一组参数再次 subscribe 视为续期。
- `internal/delivery` 的 worker 逐个订阅按顺序投递：
  - 使用 Standard Webhooks 签名，带 `webhook-id`、`webhook-timestamp`、`webhook-signature` 和 `X-MCP-Subscription-Id`；
  - 失败时指数退避重试；
  - 按规范发 gap、terminated、verification 控制消息；
  - 过期后清理。
- 回调 URL 必须是 https，每次投递都重新解析 IP 并拒绝内网地址，除非设置了 `MWE_ALLOW_PRIVATE_CALLBACKS`。

### OAuth 授权服务器（`internal/oauth`）
- **Metadata**：
  - `/.well-known/oauth-protected-resource` 和 `/.well-known/oauth-protected-resource/mcp`：resource 为 `<public>/mcp`，authorization_servers 为 `[<public>]`。
  - `/.well-known/oauth-authorization-server`，`/.well-known/openid-configuration` 返回同一份。内容包括 `code_challenge_methods_supported:["S256"]`、`token_endpoint_auth_methods_supported:["none","client_secret_post","client_secret_basic"]`、`authorization_response_iss_parameter_supported:true`。
- **`POST /oauth/register`（RFC 7591）**：redirect_uri 只接受 https 或 loopback http。
- **`GET /oauth/authorize`**：
  - 未登录时先显示密码登录页；
  - 已登录后进入 consent 页：显示 client 名称和回调 host，可以选择已有 identity 或新建一个；
  - 用户 POST 确认后，带 `code`、`state`、`iss` 重定向回去。
  - PKCE S256 是强制的。
  - redirect_uri 精确匹配；loopback 地址忽略端口（RFC 8252）。
  - `resource` 如果传了，必须等于 MCP resource。
- **`POST /oauth/token`**：支持 `authorization_code` 和 `refresh_token`，同时校验 resource。**`POST /oauth/revoke`** 用于撤销。
- **CIMD**：不在本次范围内。用户指定了 DCR，2026-07-28 规范里 DCR 仍然是 MAY。

### Admin（密码登录与 Web UI）
- **登录**：
  - 登录页校验 `MWE_PASSWORD`（常量时间比较），按 IP 做失败退避。
  - 成功后发会话 cookie：随机 session 存库，HttpOnly，SameSite=Lax；在 https 下加 Secure。
  - admin API 要求同源 Origin，并带自定义 header 防 CSRF。
- **UI 页面**：
  - Identity 列表：新建、重命名、删除。
  - 每个 identity 的详情：
    - Webhooks：URL、轮换 key（明文只显示一次）、删除；
    - Channels：查看和编辑过滤规则、删除；
    - 已授权客户端：可以撤销；
    - 最近事件：列表加详情 JSON，通过 admin SSE 实时刷新。
  - 平台广播。

### CLI `mwe`
- **登录态**：
  - `mwe login <server-url> [--profile p]`：拉 metadata，DCR 注册，PKCE，在 loopback 回调上打开浏览器，identity 在 server 的 consent 页上选。
  - 凭据写到 `~/.config/mwe/credentials.json`，权限 0600，按 profile 区分；自动 refresh。
  - 另有 `mwe logout`、`mwe status`（调用 `whoami`）。
- **管理命令**：都是 MCP `tools/call` 的封装，只有一套 API。
  - `mwe webhooks list|create|update|rotate-key|delete`
  - `mwe channels list|create|update|delete`
- **调试命令**：`mwe events tail --channel x [--cursor c]`（基于 events/stream）、`mwe events poll`。
- **`mwe mcp [--profile p]`：stdio bridge**
  - 从 stdin 逐行读 JSON-RPC，每个请求单独 POST 到 `/mcp`：自动带 bearer（会刷新），按消息内容补全 `MCP-Protocol-Version`、`Mcp-Method`、`Mcp-Name`。
  - 把 JSON 响应或 SSE 帧原样写回 stdout（写 stdout 加锁）。
  - 收到 `notifications/cancelled` 时取消对应的 HTTP 请求；请求可以并发，长连的 `events/stream` 也不会阻塞其它请求。
  - 401 时尝试刷新一次 token，失败就返回 JSON-RPC 错误，提示先执行 `mwe login`。
- `mwe version`。

### 构建
- **Makefile**：`build`（两个二进制，`CGO_ENABLED=0`，ldflags 注入版本）、`dev`、`test`（`go vet` 加 `go test -race`）、`test-ui`、`lint`（gofmt）。
- **Dockerfile**：两阶段，`golang:1.26-alpine` 构建，`debian:12-slim` 运行；以 nonroot 用户运行，`/data` 挂卷。
- 另有 README，以及 `.env.example`（不放真实密码）。

## 实施顺序

1. 拉取 SEP-3415 原文到 `docs/spec/`，同时保存 2026-07-28 transport 和 discover 规范的摘录。
2. 搭建 `go.mod` 骨架，完成 config、store 和迁移、ident 包及测试。
3. 完成 OAuth 授权服务器、admin 登录和会话，以及 consent 页。
4. 完成 MCP transport（modern 加 legacy）和 tools。
5. 完成 ingest、events hub、channel 过滤，以及 stream 和 poll。
6. 完成 webhook 模式投递（delivery）。
7. 完成 Web UI。
8. 完成 CLI：OAuth 客户端、管理命令、events tail，以及 bridge。
9. 补齐 Makefile、Dockerfile 和 README。

## 验证（全部通过才算完成）

1. **`go test -race ./...`**，覆盖以下用例：
   - identifier 和保留 identifier 的校验；
   - include、exclude、all 过滤，以及广播绕过过滤；
   - OAuth 全流程：DCR → authorize → token → refresh 轮换；PKCE 错误、redirect 不匹配、resource 不匹配、refresh 重放撤销 family；同一 identity 下多次授权；
   - MCP header 和版本错误码；server/discover 中两种 events 能力声明；legacy initialize；
   - events/stream 的帧顺序（active → 回放 → 实时 → heartbeat）、channel 更新即时生效、channel 删除后收到 terminated、按 cursor 续传、retention 过期时 truncated；
   - poll 分页；
   - webhook 模式签名：用 Standard Webhooks 算法独立验签；SSRF 拒绝内网地址；
   - ingest 三种 key 传法、401、413、敏感 header 不入库。
2. **gofmt 和 go vet**，并用 `GOOS=linux` 交叉编译通过。
3. **端到端**：在本地启动 `mwe-server`，`MWE_PUBLIC_URL=http://localhost:8080`。
   - 用 Playwright 走完 `mwe login`：输入密码、新建 identity、完成授权。
   - 依次验证：`mwe webhooks create` → curl webhook（分别用 header、query、bearer 三种方式传 key）→ `mwe events tail` 收到事件 → `mwe channels update` 改成 exclude 后不再收到 → 在 UI 发平台广播后仍然能收到。
   - 用 stdio 管道驱动 `mwe mcp` bridge，完成 server/discover、tools/call 和 events/stream。
4. **第三方客户端互通**：在 `/tmp` 下用 `@mastra/mcp` ≥2.5 写脚本，带 bearer 连接 `/mcp`，跑通 push（events/stream）和 poll。如果 conformance#521 的 server 套件能跑，也跑一遍。
5. **UI**：Playwright 截图检查登录、consent、identity 详情、事件页，浅色和深色两种模式都看。

除非用户另外要求，不 commit。
