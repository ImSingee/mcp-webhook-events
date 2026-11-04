# Admin UI ↔ Server 契约

前端（`internal/web/assets/**`）和后端（其余所有代码）并行开发，以本文为唯一契约。
如需变更，改本文并在两侧同步实现；不要在任何一侧私自偏离。

## 文件归属

| 区域 | 归属 |
|---|---|
| `internal/web/assets/**`（HTML/CSS/JS/图标/manifest） | 前端 |
| `internal/web/*.go`（`//go:embed assets`、静态文件 handler、ETag + `?v=hash` 版本化、`-tags dev` 读磁盘）以及其余全部 Go 代码、go.mod、Makefile、Dockerfile、README | 后端 |

双方都不修改对方区域的文件。`internal/web/assets/index.html` 当前是占位文件，由前端覆盖。

## 页面路由（后端负责路由，页面内容来自 assets）

| 路径 | 文件 | 说明 |
|---|---|---|
| `GET /` | `index.html` | 管理 SPA（hash 路由，如 `#/identities/<id>`、`#/events`、`#/broadcast`）。未登录时 302 到 `/login?next=<原路径>` |
| `GET /login` | `login.html` | 密码登录页。登录成功后跳转到 `next`（只允许以 `/` 开头的站内路径，不允许 `//`） |
| `GET /consent?request=<ar_id>` | `consent.html` | OAuth 授权确认页。未登录时 302 到 `/login?next=/consent?request=...` |
| 其它静态资源 | `assets/` 下的同名文件 | 例如 `/app.css`、`/app.js` |

页面引用的 JS/CSS 用相对于根的普通路径（`<script src="/app.js">`），由后端中间件改写成 `?v=hash`。不使用 CDN 和外部资源。

## 通用约定

- 所有 `/api/*` 请求和响应都是 JSON（SSE 除外），时间使用 RFC 3339 UTC 字符串。
- 认证使用 HttpOnly cookie `mwe_session`，前端不读也不写它。
- 除 `POST /api/login` 外，所有 `/api/*` 都要求已登录，未登录返回 `401`。
- 所有非 GET 请求必须带 header `X-MWE-Request: 1`，并且是同源请求，否则返回 `403`。这是 CSRF 防护。
- 错误响应统一为 `{"error":{"code":"<snake_case>","message":"<人类可读>"}}`。`code` 的取值包括 `unauthorized`、`forbidden`、`not_found`、`conflict`、`invalid_argument`、`rate_limited` 和 `internal`。
- 字段命名使用 snake_case。

## Session

- `POST /api/login`
  - 请求体 `{"password":"..."}`。
  - 成功返回 `204` 并设置 cookie；密码错误返回 `401`；失败过多返回 `429`，body 中 `error.retry_after_seconds` 为 int。
- `POST /api/logout`：返回 `204`。
- `GET /api/meta`：返回 `{"version":"...","public_url":"https://x","mcp_url":"https://x/mcp"}`。
  - 未登录也可访问，供登录页显示版本号。

## Identities

Identity 对象：
```json
{"id":"idn_…","name":"my-laptop-claude","created_at":"…","webhook_count":2,"channel_count":1,"authorization_count":3,"last_event_at":"…|null"}
```
- `GET /api/identities` → `{"identities":[Identity]}`，按 `created_at` 升序。
- `POST /api/identities`，请求体 `{"name":"..."}` → `201 Identity`；重名返回 `409 conflict`。name 为 1–64 字符的任意文本，首尾空白会被去掉。
- `PATCH /api/identities/{id}`，请求体 `{"name":"..."}` → `Identity`。
- `DELETE /api/identities/{id}` → `204`。级联删除该 identity 的 webhooks、channels、授权（tokens）、订阅和事件。

## Webhooks（`{iid}` = identity id）

Webhook 对象：
```json
{"id":"whk_…","identifier":"github-push","name":"GitHub push","description":"…","url":"https://x/hooks/<token>","created_at":"…","updated_at":"…","last_event_at":"…|null","event_count":12}
```
- `GET /api/identities/{iid}/webhooks` → `{"webhooks":[Webhook]}`。
- `POST /api/identities/{iid}/webhooks`，请求体 `{"identifier":"...","name":"...","description":"..."}` → `201 {"webhook":Webhook,"key":"<明文，仅此一次>"}`。
  - identifier 必须匹配 `^[a-z0-9]+(-[a-z0-9]+)*$`，且不超过 64 字符；不合法返回 `400 invalid_argument`；与已有 identifier 重复返回 `409 conflict`。
- `PATCH /api/identities/{iid}/webhooks/{wid}`，请求体 `{"name"?:..., "description"?:...}` → `Webhook`。identifier 不可修改。
- `POST /api/identities/{iid}/webhooks/{wid}/rotate-key` → `{"webhook":Webhook,"key":"<新明文>"}`，旧 key 立即失效。
- `DELETE /api/identities/{iid}/webhooks/{wid}` → `204`。

key 有三种传法，UI 应展示用法示例：header `X-Webhook-Key: <key>`、`Authorization: Bearer <key>`，或 query `?key=<key>`。

## Channels

Channel 对象：
```json
{"id":"chn_…","name":"ci","description":"…","mode":"all|include|exclude","identifiers":["github-push",":system"],"created_at":"…","updated_at":"…","active_streams":1,"subscription_count":0}
```
- `GET /api/identities/{iid}/channels` → `{"channels":[Channel]}`。
- `POST /api/identities/{iid}/channels`，请求体 `{"name":"...","description"?:"","mode":"all","identifiers"?:[]}` → `201 Channel`。
  - name 的规则与 webhook identifier 相同。
  - `mode=all` 时 identifiers 必须为空。
  - identifiers 中的元素可以是普通 identifier，也可以是 `^:[a-z0-9][a-z0-9:-]*$` 形式的保留 identifier。
- `PATCH /api/identities/{iid}/channels/{cid}`，请求体 `{"description"?, "mode"?, "identifiers"?}` → `Channel`。修改立即对在线订阅生效。
- `DELETE /api/identities/{iid}/channels/{cid}` → `204`。在线订阅会收到 terminated。

## Authorizations（OAuth 授权）

同一个 identity 下可以有多条授权，每条对应一个 refresh token family。

Authorization 对象：
```json
{"id":"auf_…","client_id":"…","client_name":"Claude Code","redirect_host":"localhost","created_at":"…","last_used_at":"…|null"}
```
- `GET /api/identities/{iid}/authorizations` → `{"authorizations":[Authorization]}`。
- `DELETE /api/identities/{iid}/authorizations/{aid}` → `204`。立即撤销该授权的 access token 和 refresh token。

## Event subscriptions（SEP-3415 webhook 投递模式）

Subscription 对象：
```json
{"id":"sub_…","channel":"ci","url":"https://agent.example/cb","status":"active|failing|expired|terminated","expires_at":"…","failure_count":0,"last_delivery_at":"…|null","last_error":"…|null","created_at":"…"}
```
- `GET /api/identities/{iid}/subscriptions` → `{"subscriptions":[Subscription]}`。
- `DELETE /api/identities/{iid}/subscriptions/{sid}` → `204`。

## Events

Event 对象：
```json
{
  "id":"evt_…","seq":1234,
  "identity_id":"idn_…|null",        // null = 平台广播
  "identity_name":"…|null",
  "identifier":"github-push",        // 也可能是 ":system" 等保留 identifier
  "kind":"webhook|system",
  "received_at":"…",
  "data":{ ... }                     // 与推给 Agent 的 MCP event data 完全相同，见下
}
```
- `GET /api/events?identity_id=&identifier=&before=<seq>&limit=50` → `{"events":[Event],"next_before":<seq>|null}`。
  - 结果按 seq 倒序，所有过滤参数都是可选的；`identity_id=_broadcast` 表示只看广播事件。
- `GET /api/events/stream?identity_id=` 是 SSE 接口，返回 `text/event-stream`。
  - 每条新事件发一帧 `event: event` 加 `data: <Event JSON>`。
  - 每 20 秒发一次 `: ping` 注释帧。
  - 前端用 `EventSource` 订阅，断线后自动重连。

### Event `data` 结构（MCP 事件 `webhook.received` 的 data 字段）

```json
{
  "identifier":"github-push",
  "kind":"webhook",
  "webhook":{"name":"GitHub push"},           // kind=system 时为 null
  "received_at":"…",
  "request":{                                  // kind=system 时为 null
    "method":"POST",
    "query":{"a":["1"]},                       // 已移除 key
    "headers":{"Content-Type":["application/json"]}, // 已移除 X-Webhook-Key / Authorization
    "content_type":"application/json",
    "body_encoding":"json|text|base64|none",
    "body": <JSON 值 | 字符串 | base64 字符串 | null>
  },
  "message": "…|null",                         // kind=system 时的广播正文
  "title": "…|null"
}
```

## Broadcast

- `POST /api/broadcast`，请求体 `{"identifier"?:":system","title"?:"...","message":"..."}` → `201 {"event_id":"evt_…"}`。
  - identifier 必须是保留形式（以 `:` 开头），默认为 `:system`。
  - 广播投递给所有 identity 的所有在线订阅，不经过 channel 过滤。

## OAuth consent

后端处理 `GET /oauth/authorize` 时，先校验参数（client、redirect_uri、PKCE、resource），然后把请求保存为待确认请求 `ar_…`，有效期 10 分钟，并 302 到 `/consent?request=ar_…`。如果参数校验失败且无法安全重定向，后端直接渲染一个简单的错误文本页，不需要前端参与。

- `GET /api/oauth/requests/{id}` 返回：
  ```json
  {"id":"ar_…","client":{"id":"…","name":"Claude Code","redirect_uri":"http://localhost:53122/callback","redirect_host":"localhost"},
   "scope":"mcp","resource":"https://x/mcp","expires_at":"…",
   "identities":[{"id":"idn_…","name":"…","authorization_count":1}]}
  ```
  请求过期或不存在时返回 `404 not_found`。
- `POST /api/oauth/requests/{id}/approve`，请求体 `{"identity_id":"idn_…"}` 或 `{"new_identity_name":"..."}`（二选一）→ `{"redirect_url":"<带 code/state/iss 的回调地址>"}`。前端收到后执行 `location.assign(redirect_url)`。
- `POST /api/oauth/requests/{id}/deny` → `{"redirect_url":"<带 error=access_denied&state&iss 的回调地址>"}`。

consent 页必须醒目展示 `client.name` 和 `redirect_host`；如果 `redirect_host` 是 loopback 地址，要注明“本机应用”。
