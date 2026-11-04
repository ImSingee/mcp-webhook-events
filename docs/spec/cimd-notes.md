# CIMD：规范要求与实现对照

依据：
- `draft-ietf-oauth-client-id-metadata-document-03.txt`（下称 CIMD），本目录原文；
- MCP 2026-07-28 `mcp-2026-07-28-authorization/client-registration.mdx` 与 `security-considerations.mdx`（下称 MCP）。

实现在 `internal/oauth/cimd.go`，接入点在 `internal/oauth/oauth.go`（authorize、token、revoke）。

## Client Identifier URL（CIMD §3、§9.1、§10.1；MCP）

| 要求 | 实现 |
|---|---|
| MUST https；MUST NOT userinfo；MAY port；MUST path ≠ `/`；MUST NOT `.`/`..` 段；SHOULD NOT query；MUST NOT fragment | `CheckClientIDURL`：要求原文以 `https://` 开头；含 `#`（含空 fragment）即拒；解析后 `User != nil` 即拒；path 为空或 `/` 即拒；逐段（含百分号编码解码后）检查 `.`/`..`；query 允许（SHOULD NOT 是对客户端的要求）|
| MUST 简单字符串比较，AS MUST NOT 规范化 | 文档 `client_id` 与请求里的原始字符串直接比较；抓取时也用原始 URL |
| §9.1 自己生成的 client_id 不以 `https://` 开头 | DCR 的 id 是 `cli_…`，不含 `:`；`IsClientIDURL` 以是否含 `:` 区分，含 `:` 的一律按 CIMD 处理（不合法就拒），不会落到 DCR 查库 |
| §10.1 SHOULD 拒绝等于自身 issuer 或有信任关系的服务器标识 | 等于 issuer 或 MCP resource（`<public>/mcp`）即拒 |

## 抓取（CIMD §6、§6.1、§10.7、§10.7.1、§10.11、§11.1）

| 要求 | 实现 |
|---|---|
| SHOULD 发 `Accept: application/json` | 已发送；不带 cookie 和用户信息 |
| MUST 只接受 200；MUST NOT 自动跟随重定向 | 非 200 一律失败；3xx 为终止性失败；HTTP 客户端 `CheckRedirect` 返回 `ErrUseLastResponse` |
| 内容为 JSON，可用 `application/<x>+json` | 只接受 `application/json` 与 `application/*+json`；必须解析为 JSON 对象 |
| MUST NOT 抓取解析到 RFC 6890 特殊用途地址的 URL | 复用 `delivery.Guard`：每次连接自行解析 DNS、逐个校验、直连校验过的 IP，不走环境变量代理 |
| 开发例外：AS 自身在回环地址时 MAY 放开回环；MUST NOT 用于生产 | `MWE_ALLOW_PRIVATE_NETWORK` 且 `MWE_PUBLIC_URL` 为回环地址时，`Guard.AllowLoopback` 只放开回环地址（其他私网段仍拒绝）；URL 仍须 https |
| §10.11 SHOULD 限制读取量，推荐 5 KB | 最多读 5120 字节，超过即终止性失败 |
| §6.1 瞬时（网络、超时）与终止（格式、校验、信任）两类 | 网络错误、超时、5xx、429 为瞬时；SSRF 拒绝、TLS 证书不可信、3xx/4xx、非 JSON、过大、校验失败为终止 |
| 失败时 MUST NOT 重定向到客户端，SHOULD 告知用户 | authorize 直接渲染错误页（400），不发 Location |
| token 端点 MUST 返回 `invalid_client`，瞬时失败可 503 | 终止性失败返回 401 `invalid_client`；瞬时失败且没有可用快照时返回 503 `temporarily_unavailable` |
| 瞬时失败 SHOULD NOT 使已有信任和 refresh token 失效，SHOULD NOT 丢弃已缓存的有效元数据 | token 端点（code 兑换、refresh）遇到瞬时失败时沿用上次校验通过的快照；authorize 不沿用（§6.1「SHOULD abort」）|
| client_id 不一致的终止性失败 SHOULD 立即使 refresh token 失效 | 撤销该客户端全部 family（access 和 refresh token 一起），并通知在线流和 webhook 订阅 |

## 缓存（CIMD §6.2）

| 要求 | 实现 |
|---|---|
| SHOULD 遵守 HTTP 缓存头；`Expires` 可不理会 | `s-maxage` 优先于 `max-age`（服务端缓存由所有用户共享），减去 `Age`；`no-store`/`no-cache` 视为 0；忽略 `Expires` |
| SHOULD 设最大有效期；无指示时设最小有效期 | 上限 24 小时；无缓存头时 10 分钟；显式的较小值抬到 1 分钟（§6.2 允许的抓取限速）|
| MUST NOT 缓存错误响应和无效文档 | 只有校验通过才写入快照（`oauth_clients` 上 `kind='cimd'` 的行）；失败不写入、不延长已有快照 |
| SHOULD 定期重新抓取 | 快照过期后下一次使用时重新抓取；同一 URL 的并发抓取合并为一次 |

## 文档内容（CIMD §4、§4.1、§4.4、§5、§6；MCP）

| 要求 | 实现 |
|---|---|
| `client_id` MUST 与 URL 一致 | 不一致即终止性失败，并标记为 mismatch |
| MCP：AS MUST 校验结构有效且含必填字段（`client_id`、`client_name`、`redirect_uris`）| 缺 `client_name`（或为空白）、缺或空 `redirect_uris` 即拒；`redirect_uris` 每项必须是 https 或回环 http，不能有 fragment |
| §4.1 MUST NOT 含 `client_secret`、`client_secret_expires_at`；认证方式 MUST NOT 含共享密钥类；`jwks` 与 `jwks_uri` 不能同时出现 | 三条都校验，违反即拒；`client_secret*` 前缀的方法一律视为共享密钥类 |
| §5 认证方式：识别 `token_endpoint_auth_methods_supported`；缺失时可读 `token_endpoint_auth_method`；两者都有时后者须在前者中；都没有时 MUST 视为 `none`；MUST NOT 套用 RFC 7591 的默认值 | 按此顺序确定候选；两者矛盾即拒；候选中没有 `none` 即拒（本服务只支持 public client）；候选含 `none` 和其他方法时按 `none` 接受（§5「SHOULD select one … it supports」）|
| §5 方法为 `none` 时，客户端在 token 请求中带了客户端认证 MUST `invalid_client` | 带 Basic 认证、`client_secret` 或 `client_assertion` 即返回 401 `invalid_client` |
| §6 `grant_types`、`response_types` 取与 AS 支持的交集，为空 MUST `invalid_client` | `grant_types` 缺省为 `["authorization_code"]`，交集必须含 `authorization_code`；`response_types` 必须含 `code` |
| §4.4、§10.7 informative URI 只认已知 scheme | `client_uri`、`logo_uri` 只在是 https 绝对 URL 时保存 |
| §10.9 展示 logo 前 MUST 由 AS 抓取并托管 | 不展示 logo，API 也不返回 `logo_uri` |

## redirect_uri（CIMD §4.2 → RFC 9700 §4.1.3 → RFC 8252 §7.3；MCP）

CIMD §4.2：

> the authorization server MUST ensure that the redirect URL in an authorization request is an exact match (using simple string comparison) of a registered redirect URL. An exception is made for redirect URIs on the loopback network interface, which allow for randomly assigned ports. See Section 4.1.3 of [RFC9700] for details.

RFC 9700 §4.1.3：

> The only exception is native apps using a localhost URI: In this case, the authorization server MUST allow variable port numbers as described in Section 7.3 of [RFC8252].

RFC 8252 §7.3：

> Loopback redirect URIs use the "http" scheme and are constructed with the loopback IP literal and whatever port the client is listening on. … The authorization server MUST allow any port to be specified at the time of the request for loopback IP redirect URIs

实现（`CIMDRedirectMatches`）：
- 先做简单字符串比较；
- 唯一例外：双方都是 `http`，主机名**逐字相同**且属于 `127.0.0.1`、`::1`、`localhost`（RFC 9700 的「localhost URI」），path、query 逐字相同，不带 userinfo 和 fragment 时，端口可以不同；
- 与 DCR 规则（`RedirectMatches`）的区别：不对主机名做大小写折叠，只认这三个主机名，不认其他 127/8 地址。

真实样本：Claude Code 的文档（`https://claude.ai/oauth/claude-code-client-metadata`，2026-11-04 抓取）登记 `http://localhost/callback` 和 `http://127.0.0.1/callback`，不带端口，运行时用随机端口回调，这条规则可以覆盖，见 `TestClaudeCodeDocument`。

## consent（CIMD §10.6、§10.10；MCP Localhost Redirect URI Risks）

| 要求 | 实现 |
|---|---|
| CIMD §10.6 SHOULD 显示 client_id 的主机名 | consent API 和授权列表返回 `metadata_host` |
| CIMD §10.10 名称、logo 等由客户端自称 | 契约要求前端注明名称由 `metadata_host` 上的文档自称、未经审核 |
| MCP SHOULD 对仅回调 localhost 的客户端额外警告；MUST 清楚显示 redirect URI 的主机名 | CIMD 客户端的本次 redirect_uri 是回环地址时，返回 `warnings: [{"code":"localhost_redirect", …}]`；`redirect_host` 照旧返回 |

## authorization response（CIMD §7）

`iss` MUST 出现在授权响应中：沿用既有实现，成功和错误重定向都带 `iss`。
