# HTTPS Relay 设计冻结（v1）

状态：**已冻结，可进入 TDD 实施；本文件不代表已部署或已通过真实边缘验收。**

## 1. 目标

建立唯一生产出口：

```text
客户端
→ Cloudflare Worker
→ 固定 HTTPS Relay 入口
→ VPS 上的 Rust Relay
→ 运行时动态 HTTPS 上游
→ Rust Relay
→ Worker
→ 客户端
```

必须满足：

- 上游 hostname、path、query 由客户端运行时传入，不维护逐域 route table。
- 上游只允许 `https://`，端口固定为 `443`。
- 所有生产外连都经 VPS；Relay 缺失、认证失败或不可达时 fail-closed，绝不回退 Cloudflare direct egress。
- Worker 不再实现 SOCKS5、CONNECT、`cloudflare:sockets`、`startTls()` 或自制 HTTP/1.1 framing。
- Rust Relay 保留现有 `rustls + aws-lc-rs + HTTP/2` 出站能力和 TLS/HTTP2 指纹契约。
- 普通响应、压缩响应与 SSE 必须增量回传，不等待完整响应体。
- Relay 不是开放代理：入口必须有客户端鉴权；Worker→Relay 必须有独立 HMAC 鉴权、重放防护、SSRF 防护、并发与容量限制。

## 2. 非目标

v1 明确不支持：

- 任意 TCP 字节流、HTTP CONNECT、WebSocket 隧道、UDP、QUIC 透传。
- HTTP 明文上游、自定义上游端口、客户端指定代理链。
- Relay 内部自动跟随重定向。
- 在 VPS 上隐藏业务明文。VPS 是受信任的应用层中继，会看到上游 `Authorization`、请求体及响应内容。
- 请求体边接收边转发。v1 为了在出站前完成 HMAC 和身份投影，采用**有界缓冲请求、流式响应**。

## 3. 当前代码基线与单一职责

### 3.1 Worker：`/opt/codex-worker-relay`

保留并由 Worker 单独负责：

- `/<target-hostname>/<path>?<query>` 动态目标解析。
- 客户端入口鉴权。
- Codex identity header canonicalization。
- 现有 JSON `client_metadata` 投影，避免改变已验证身份契约。
- 请求体上限读取。
- Worker→Relay 线协议构造与 HMAC 签名。
- 客户端可见错误映射。
- 上游重定向 `Location` 重写，保证自动跟随时仍回到 Worker。

最终生产版本不再保留可达的 direct 或 SOCKS5 出口分支。旧实现只通过 Git 历史回滚，不通过运行时 fallback 保留。

### 3.2 Rust：`/opt/codex-egress-relay`

现有 `codex-egress-relay` 二进制保持原行为，继续作为已验证 oracle 和回滚资产。

新增独立二进制 `codex-https-relay`，由它单独负责：

- HMAC、时间窗、nonce 重放校验。
- 动态 HTTPS target 解析及网络策略。
- DNS 解析后 IP 校验和连接地址钉扎。
- 出站 TLS/SNI/证书校验、HTTP/2、连接池。
- 请求转发、响应头过滤和响应 body streaming。
- 并发、连接、响应头、读空闲、响应大小限制。
- 脱敏结构化日志。

新二进制**不得再次合成 Codex identity 或修改 JSON body**。身份只由 Worker 生成；Rust 只从已签名的 canonical header block 重建业务 headers，并转发已签名 body。现有固定上游二进制继续使用原 `identity.rs`，两条入口互不影响。

### 3.3 共享但不重复拥有的契约

- `tls.rs` 中的 rustls/aws-lc-rs ClientHello 与 ALPN 构造是 Rust 仓库内唯一 TLS 配置源。
- Worker 和 Rust 分别实现 v1 签名算法，但必须使用同一份版本化规范与固定测试向量。
- 线协议任何不兼容变更必须提升版本；禁止静默猜测或兼容未知版本。

## 4. 外部 Worker 契约

### 4.1 URL

保持现有格式：

```text
https://<worker-origin>/<target-hostname>/<target-path>?<query>
```

示例：

```text
https://worker.example/api.openai.com/v1/responses?stream=true
→ https://api.openai.com/v1/responses?stream=true
```

约束：

- hostname 沿用当前 `src/target.ts` 校验。
- 目标 scheme 固定 `https`，端口固定 `443`，fragment 禁止。
- v1 target URL 序列化后最大 `4096` 字节。
- 支持上游方法：`GET`、`HEAD`、`POST`、`PUT`、`PATCH`、`DELETE`、`OPTIONS`。
- `CONNECT`、`TRACE` 及其他未支持方法返回 `405`。

### 4.2 客户端入口鉴权

生产入口要求：

```text
X-Codex-Relay-Token: <opaque random token>
```

- Worker Secret：`INGRESS_AUTH_TOKEN`。
- token 至少 32 个随机字节，以 base64url 或等价无歧义格式保存。
- Worker 使用恒定时间比较。
- 缺失或错误返回 `401`，通用错误体，不说明 token 是否存在。
- 此 header 在 Worker 内消费，绝不进入身份投影、canonical header block、Relay 请求日志或上游请求。
- 若实际客户端不能配置该 header，则不得将 Worker 暴露公网；需先增加受控本地适配层。这不是允许使用 URL/query secret 的理由。

### 4.3 请求头投影

Worker：

1. 删除客户端传入的所有 `x-codex-relay-*` 控制头。
2. 删除 hop-by-hop 和平台来源头。
3. 执行现有 Codex identity/header/body 投影。
4. 将最终业务 headers 规范化为一个有界 canonical header block；该 block 经 base64url 放入控制头并由 HMAC 整体绑定。

必须删除且不得向上游转发：

```text
host
content-length
connection
keep-alive
proxy-authenticate
proxy-authorization
proxy-connection
te
trailer
transfer-encoding
upgrade
cf-connecting-ip
cf-ray
cf-visitor
cdn-loop
forwarded
x-forwarded-for
x-real-ip
x-codex-relay-*
```

`Authorization`、`Content-Type`、`Accept`、`Accept-Encoding` 及 Codex identity headers 可进入 canonical header block，并由 HMAC 绑定。它们**不作为外层 Relay 请求的同名业务头发送**，避免 Cloudflare 或中间层对 `Accept-Encoding` 等字段的规范化/改写导致验签歧义；Relay 验签后再重建上游 headers。

## 5. Worker→Relay v1 线协议

### 5.1 外层请求

```text
POST /v1/forward HTTP/2
Host: <relay-hostname>
X-Codex-Relay-Version: 1
X-Codex-Relay-Key-Id: <key-id>
X-Codex-Relay-Timestamp: <unix-seconds>
X-Codex-Relay-Nonce: <base64url-16-random-bytes>
X-Codex-Relay-Method: <upstream-method>
X-Codex-Relay-Target: <base64url-utf8-absolute-https-url>
X-Codex-Relay-Body-SHA256: <base64url-sha256(raw-body)>
X-Codex-Relay-Headers: <base64url-canonical-header-block>
X-Codex-Relay-Signature: <base64url-hmac-sha256>
Content-Type: application/octet-stream

<raw upstream request body>
```

规则：

- 外层方法固定 `POST`，外层 path 固定 `/v1/forward`。
- 上游 method/target 放在控制头，body 是投影后的原始字节，不使用 JSON/base64 envelope。
- 所有 base64url 均无 padding。
- canonical header block 解码后最大 `32768` 字节。
- header 名小写、去重、ASCII 升序；每行格式为 `<name>:<normalized-value>\n`。
- Relay 只向上游转发该 block 中的 headers。Cloudflare 自动增加、删除或改写的外层 headers 一律不参与业务转发。
- `host`、`content-length`、hop-by-hop、平台来源头及控制头不得进入 canonical header block。
- 外层 `Content-Type: application/octet-stream` 只描述 Relay transport body；真正的上游 `Content-Type` 从 canonical header block 恢复。

### 5.2 Canonical Request

UTF-8 字节串，行分隔符严格为 `\n`：

```text
codex-relay-v1
<key-id>
<timestamp>
<nonce>
<METHOD>
<base64url-target>
<body-sha256>
<base64url-canonical-header-block>
```

header value 规范化：

- 去除首尾 HTTP optional whitespace。
- 连续空格或 tab 折叠为单个 ASCII 空格。
- CR/LF 非法，直接拒绝。
- 不进行 Unicode case folding；header name 已是小写 ASCII。
- canonical header block 必须以 `\n` 结束；空 header 集合编码为空字节串。
- Relay 对解码后的 block 重新执行顺序、唯一性、禁止名单和规范化校验；不能只相信 Worker 声明。

签名：

```text
HMAC-SHA256(secret, canonical-request)
```

Relay 先验证：协议字段格式、body 上限、body digest、签名、时间窗、nonce；全部通过后才允许发起 DNS 或上游连接。

### 5.3 时间窗、重放与密钥轮换

- 默认允许时钟偏差：`±60s`。
- nonce：128-bit CSPRNG，按 `(key-id, nonce)` 唯一。
- Relay 在内存保存已接受 nonce 至少 `120s`；重复 nonce 返回协议错误，不访问上游。
- 单实例重启会清空 nonce cache，但 HMAC secret 不泄露且重放窗口仅 60 秒；该残余风险在 v1 接受。若未来多副本或更高对抗等级，改用共享 durable replay store 并提升协议小版本。
- Relay 同时接受 current/previous 两个 key slot；Worker 只使用 current。
- 轮换顺序：Relay 加 previous/current → Worker 切 current → 观察 → Relay 移除 previous。

## 6. Relay 目标与 SSRF 策略

Relay 接受 target 前必须满足：

- 解码后是绝对 `https://` URL。
- 无 userinfo、无 fragment、无自定义 port。
- hostname 符合 Worker 相同语义；URL 长度不超过 4096 字节。
- method 在 v1 allowlist。

DNS/连接要求：

1. 使用 Relay 自有 resolver 解析 hostname。
2. 校验解析出的**全部**地址；只要混入一个禁止地址，整次请求失败。
3. 将同一次校验通过的地址直接交给 reqwest connector；不得校验一次后让另一个 resolver 重新解析。
4. 禁止系统 HTTP/HTTPS proxy，reqwest client 必须显式 `no_proxy()`。
5. 禁止自动 redirect，必须 `redirect(Policy::none())`。

至少禁止：

- IPv4/IPv6 unspecified、loopback、private/ULA、link-local。
- carrier-grade NAT、multicast、broadcast、reserved、benchmark、documentation ranges。
- IPv4-mapped IPv6 中映射到禁止 IPv4 的地址。
- 云 metadata、localhost 及 IANA special-purpose 地址。

目标是“任意公网 HTTPS hostname”，不是“任意 IP/端口”。

## 7. 出站 HTTP/TLS 与流式语义

### 7.1 TLS/HTTP2

- 从现有 `tls.rs` 提取/复用同一 `rustls::ClientConfig`。
- 继续使用 `aws-lc-rs`，保留 `ecdsa_secp521r1_sha512 (0x0603)`。
- ALPN 顺序继续为 `h2`、`http/1.1`。
- 禁止 HTTP/2 prior knowledge；必须通过 TLS ALPN。
- 禁止自动 gzip/deflate/brotli 解压；保留业务 `Accept-Encoding` 和响应 `Content-Encoding`。
- 使用共享 client/connection pool；按 hostname 正常隔离连接池。

### 7.2 超时

不能沿用会覆盖完整响应体生命周期的单一 total timeout，否则长 SSE 会被定时截断。

默认建议值（均可配置）：

- Worker 等待 Relay 响应头：`120s`。
- Relay DNS+connect+TLS+请求上传+响应头：`120s`。
- TCP connect：`10s`。
- 响应 body read idle：`180s`，每次成功读后重置。
- SSE/流式总时长：不设短 total deadline；由 read-idle、客户端断开和可配置最大连接时长控制。

Worker 在 `fetch()` 返回响应头后清除 setup timeout，不得让 setup timer 杀死已建立的 SSE。

### 7.3 请求与响应容量

- Worker 与 Relay 默认请求体上限均为 `10 MiB`，取两者较小值。
- 两端都使用有界增量读取：超过上限立即停止并返回 `413`；禁止先无限制 `arrayBuffer()` 再检查。
- Relay 默认并发上限建议 `64`，可配置；满载返回控制面 `429`，不访问上游。
- 非 SSE 响应建议默认上限 `64 MiB`；SSE 使用连接时长和 idle timeout。达到流式上限时关闭流并记录脱敏错误，不能伪造完整成功。

### 7.4 响应 streaming

- Rust：`reqwest::Response::bytes_stream()` → Axum body。
- Worker：Relay `response.body` 直接作为客户端 `Response` body。
- 两段都必须保留 backpressure。
- 客户端断开时应使 Worker subrequest 和 Rust 上游 response 被 drop/cancel；真实边缘验收前只标记为待验证。

Cloudflare 官方 Streams 文档确认：直接转发 subrequest 的 `ReadableStream` 可在数据到达时增量返回，并避免整个响应缓冲；这支持上述响应路径，但不替代真实 Edge→Tunnel→VPS→上游验收。

## 8. 响应协议与错误归属

Relay 在每个响应增加控制头，且必须先删除上游同名前缀：

```text
X-Codex-Relay-Result: upstream | error
X-Codex-Relay-Error: <machine-code>       # 仅 error
X-Codex-Relay-Request-Id: <opaque-id>
```

Worker 消费并删除这些控制头，不向客户端或上游泄露。

- `Result=upstream`：状态码、允许的响应 headers、body 属于真实上游；包括上游 4xx/5xx，Worker 原样返回。
- `Result=error`：状态/body 由 Relay 生成，Worker 映射为稳定的客户端 JSON 错误。
- Relay auth、nonce、配置等内部错误对客户端统一为 `502 relay_unavailable`，不暴露鉴权细节。
- 上游 DNS/connect/TLS/protocol 失败映射 `502 upstream_error`。
- setup/header/read idle 超时映射 `504 upstream_timeout`。
- Relay 并发饱和映射 `503 relay_busy`，可附安全的 `Retry-After`。

客户端错误体保持：

```json
{
  "error": {
    "message": "...",
    "type": "..."
  }
}
```

任何错误不得包含 Relay URL、key id 之外的密钥信息、HMAC、上游 Authorization、请求体、完整 query 或底层 TLS 错误字符串。

## 9. 重定向

Relay 不跟随 redirect，返回上游 3xx。

Worker 对 `Location`：

1. 以原 target URL 为 base 解析相对或绝对地址。
2. 只接受 `https://`、无 userinfo、无自定义 port 的目标。
3. 重写为当前 Worker origin 下的动态 target 路径。
4. 非 HTTPS 或非法 Location 返回结构化 `502 invalid_upstream_redirect`，不得把客户端引向直连目标。

这样自动跟随 redirect 的客户端仍经过 Worker→VPS，不会绕过固定出口。

## 10. 配置冻结

### 10.1 Worker

```text
INGRESS_AUTH_TOKEN                 # secret，必需
EGRESS_RELAY_URL                   # 变量，必需，固定 https://.../v1/forward
EGRESS_RELAY_KEY_ID                # 变量或 secret，必需
EGRESS_RELAY_SECRET                # secret，必需
CODEX_PROXY_MAX_BODY_BYTES         # 默认 10485760
CODEX_RELAY_HEADER_TIMEOUT_MS      # 默认 120000
```

任一必需项缺失时目标请求返回 fail-closed 配置错误；不得调用 direct `fetch(target)`。

废弃并最终删除：

```text
EGRESS_PROXY_URL
CODEX_PROXY_TUNNEL_TIMEOUT_MS
```

### 10.2 Rust HTTPS Relay

```text
CODEX_RELAY_LISTEN_ADDR                  # 必需，生产用 127.0.0.1:18093
CODEX_RELAY_CURRENT_KEY_ID               # 必需
CODEX_RELAY_CURRENT_SECRET               # 必需
CODEX_RELAY_PREVIOUS_KEY_ID              # 可选，与 PREVIOUS_SECRET 必须成对
CODEX_RELAY_PREVIOUS_SECRET              # 可选，与 PREVIOUS_KEY_ID 必须成对
CODEX_RELAY_MAX_BODY_BYTES               # 默认 10485760
CODEX_RELAY_MAX_RESPONSE_BYTES           # 默认 67108864（非 SSE）
CODEX_RELAY_MAX_CONCURRENCY              # 默认 64
CODEX_RELAY_CLOCK_SKEW_SECS              # 默认 60
CODEX_RELAY_CONNECT_TIMEOUT_SECS         # 默认 10
CODEX_RELAY_RESPONSE_HEADER_TIMEOUT_SECS # 默认 120
CODEX_RELAY_STREAM_STALL_TIMEOUT_SECS    # 默认 120
```

命名说明。三个变量名与本节早期草案不同，此处以实现与已部署 env 为准：

- `CODEX_RELAY_LISTEN_ADDR`（草案曾写 `CODEX_HTTPS_RELAY_LISTEN`）。
- `CODEX_RELAY_RESPONSE_HEADER_TIMEOUT_SECS`（草案曾写 `CODEX_RELAY_HEADER_TIMEOUT_SECS`）：
  等待上游状态行的截止时间。
- `CODEX_RELAY_STREAM_STALL_TIMEOUT_SECS`（草案曾写 `CODEX_RELAY_READ_IDLE_TIMEOUT_SECS`）：
  流已开始后 chunk 之间允许的最大静默。此名称更准确，因为 reqwest 的
  `read_timeout` 是**每次读**的预算而非整段空闲窗口，两者语义不同。

`CONNECT`、`RESPONSE_HEADER`、`STREAM_STALL` 三个预算不可互相替代：前者只覆盖
连接建立，后两者都要等 socket 存在之后才开始计时，因此握手挂死只能由
`CONNECT_TIMEOUT` 兜住。

除 key id 与 secret 外，所有值都按 fail-closed 解析：格式非法或为 `0` 时启动
即失败，不静默回落到编译默认值 —— unit 文件里的笔误不得悄悄改变出口预算或
资源上限。

实际 secret 仅进入 `0600` env 文件；仓库只提交无值示例。

## 11. 部署拓扑冻结

v1 推荐沿用 Rust 仓库现有 native systemd 模式，不引入新的容器层：

```text
Cloudflare public HTTPS hostname
→ Cloudflare Tunnel
→ VPS cloudflared
→ http://127.0.0.1:18093/v1/forward
→ codex-https-relay
→ public HTTPS target:443
```

理由：

- 复用现有 Rust 构建、CI 和已审计的 systemd sandbox。
- 新服务绑定 loopback，VPS 防火墙不新增公网 relay 端口。
- 外部是 HTTPS；Cloudflare edge→cloudflared 走 Tunnel，加上应用层 HMAC。
- 原 `codex-egress-relay` 服务、端口和二进制保持运行，直到新链路通过全部验收。

Tunnel、域名、VPS、防火墙、secret 和生产 Worker 均属高风险边界；实施前必须由用户确认目标主机、域名、账户、备份和回滚。本文不授权部署。

## 12. 日志与隐私

允许记录：

- Relay 内部 request id。
- method、target hostname、上游 status。
- 阶段化错误分类、耗时、请求/响应字节计数。
- 当前 key id（不是 secret）。

禁止记录：

- `Authorization`、入口 token、HMAC secret/signature。
- 完整 URL query、请求/响应 body。
- 原始 cookie、代理/Relay URL 中可能的凭据。
- 原始 TLS/reqwest 错误若其中可能带 URL；应映射为固定 category。

Worker 不向上游转发访客来源 IP 头；Relay 只从已签名 canonical header block 重建业务 headers，Cloudflare/Tunnel 自动头不会进入上游。

## 13. 必须通过的验收场景

### 正向

- 至少三个未预配置、彼此无关的公共 HTTPS hostname 动态转发成功。
- path/query/method/body/Authorization/Codex identity 保持。
- 上游看到的公网出口为 VPS，而不是 Cloudflare Worker egress。
- 普通 JSON、gzip body、HEAD、204、上游 4xx/5xx 保持。
- SSE 首事件在流结束前抵达，多个事件增量转发，长连接正常关闭。
- 3xx Location 被重写回 Worker，后续请求仍从 VPS 出站。

### 负向

- 缺失/错误客户端 token → `401`，无 Relay subrequest。
- 缺失 Relay 配置、Relay 不可达、错误 HMAC/key、时间过期、nonce 重放 → fail-closed，无 direct fallback。
- private/loopback/link-local/metadata/mixed public+private DNS → 拒绝且无上游连接。
- 非 HTTPS、自定义端口、过长 URL、超限 body、非法 method → 明确拒绝。
- 上游 DNS/TLS/超时错误映射稳定，响应和日志不泄密。
- Relay 饱和按设计返回，现有请求不被破坏。

### 清理与审计

- Worker 与 Rust 全套 type/lint/test/build 通过。
- 敏感信息扫描排除 `.git`、`node_modules`、`target`、`dist` 后无真实 secret。
- 临时 Worker、Tunnel route、测试 secret、日志、fixture、后台 tail 清理。
- 生产 Worker 中不存在 direct/SOCKS5 可达调用路径。
- 原 Rust oracle 仍可回滚；新服务可独立停止，不影响旧服务。

## 14. 冻结决策摘要

| 事项 | v1 决策 |
|---|---|
| Relay 类型 | 应用层 HTTPS request relay |
| 动态目标 | 任意公网 HTTPS hostname，端口 443 |
| 请求 body | 有界缓冲，默认 10 MiB |
| 响应 body | 流式，SSE 增量 |
| Identity 所有者 | Worker |
| TLS/H2 所有者 | Rust Relay |
| Worker→Relay auth | HMAC-SHA256 + timestamp + nonce + canonical header block/body digest |
| 客户端→Worker auth | 独立 `X-Codex-Relay-Token` |
| SSRF | DNS 后全地址校验并将已验证地址交给 connector |
| Redirect | Relay 不跟随；Worker 重写回自身 |
| 失败策略 | 全链 fail-closed，无 direct fallback |
| 部署 | 新 Rust 二进制 + 新 systemd unit + Cloudflare Tunnel 到 loopback |
| 旧服务 | 不改行为，保留 oracle/回滚 |

## 15. 参考依据

- 当前 Worker/Rust 源码与测试，已通过现有全套门禁。
- Cloudflare Workers Web Crypto 文档：Workers 的 `crypto.subtle` 支持 HMAC sign/verify 与 SHA-256。
- Cloudflare Workers Streams 文档：可直接用 `ReadableStream` 增量回传 subrequest body，避免完整响应缓冲。
- reqwest ClientBuilder 文档：支持禁止系统 proxy、关闭自动 redirect、独立 connect/read timeout 与自定义 DNS resolver。
