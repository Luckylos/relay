# HTTPS Relay v1 实施计划

> **归档（2026-08-21）：** 本文件是历史过程记录，不描述当前架构。
> 计划已实施完成；`codex-egress-relay` 本机出口链路已退役，身份投影现由 Worker 单一持有。当前架构见 `README.md` 与 `relay-server/README.md`。

依据：`docs/https-relay-design-v1.md`

状态：**计划完成，尚未实施生产代码、VPS、Tunnel、Worker Secret 或生产切换。**

> **已被后续修订取代的部分（2026-08-21）**：本文档中所有关于
> `X-Codex-Relay-Token` / `INGRESS_AUTH_TOKEN` 的入口鉴权要求均已作废。客户端入口
> 现为开放（无客户端凭据、无自定义 header），改由可选变量
> `ALLOWED_UPSTREAM_HOSTS` 限制可达上游主机。现行契约见
> `docs/https-relay-design-v1.md` 第 4.2 / 4.2.1 节与 `codex-worker/README.md`、
> `claude-worker/README.md`。
> 本文档保留原文作为实施历史，不再作为入口契约依据。

原则：每个切片严格 RED → GREEN → REFACTOR；每个切片独立提交；旧 Rust 服务和当前生产入口始终保持可回滚。

## 0. 实施前基线与停止条件

### 目标仓库

- Worker：`/opt/codex-worker-relay`
- Rust：`/opt/codex-egress-relay`

### 基线门禁

```bash
cd /opt/codex-worker-relay
npm run check
git status --short --branch
git diff --check

cd /opt/codex-egress-relay
jobs=$(( ($(nproc) + 1) / 2 ))
CARGO_BUILD_JOBS="$jobs" cargo fmt --all -- --check
CARGO_BUILD_JOBS="$jobs" cargo clippy --all-targets -- -D warnings
CARGO_BUILD_JOBS="$jobs" cargo test --all-targets
git status --short --branch
git diff --check
```

停止并请求用户确认，如果下一步涉及：

- 首次连接/修改目标 VPS。
- Cloudflare Tunnel、DNS、Worker production route、secret 或生产切换。
- 停止/重启现有 `codex-egress-relay`。
- 发现实际客户端不能注入 `X-Codex-Relay-Token`。
- 真实上游契约要求自定义端口、WebSocket 或非 HTTPS。

## Slice 1：冻结跨语言协议测试向量

### 目标

先证明 TypeScript 和 Rust 对 canonical request、SHA-256、HMAC、base64url、canonical header block 的解释一致，不接网络。

### Worker 文件

创建：

- `test/fixtures/relay-protocol-v1.json`
- `src/relay/protocol.ts`
- `src/relay/signing.ts`
- `test/relay-signing.test.ts`

测试向量至少包含：

- 空 body。
- JSON body。
- 多个业务 headers，乱序输入后形成相同 canonical header block。
- header value 首尾空白和内部 tab/多空格。
- canonical header block base64url 编码与 32 KiB 上限。
- 非 ASCII URL 经 URL percent-encoding 后再 base64url。
- 单字节变化导致签名变化。

### Rust 文件

创建：

- `relay_protocol.rs`
- `relay_auth.rs`
- `tests/fixtures/relay-protocol-v1.json`（内容与 Worker fixture 完全一致）

修改：

- `Cargo.toml`：仅加入协议测试需要的最小依赖，例如 `base64`、`hmac`、`sha2`。

### RED

```bash
cd /opt/codex-worker-relay
./node_modules/.bin/vitest run test/relay-signing.test.ts

cd /opt/codex-egress-relay
CARGO_BUILD_JOBS="$jobs" cargo test relay_protocol
```

先观察缺少实现或断言失败。

### GREEN

- 两端产生与 fixture 完全一致的 canonical bytes、body digest、signature。
- Rust 使用恒定时间 MAC verify。
- 未知协议版本、重复/非法 header、未排序 header block、CR/LF、padding base64url 均拒绝。

### 提交建议

```text
Worker: test: freeze HTTPS relay v1 signing vectors
Rust:   test: freeze HTTPS relay v1 signing vectors
```

## Slice 2：Rust Relay 鉴权与重放门禁（无上游连接）

### 目标

新增独立 binary 的认证壳层；认证失败时绝不触发 DNS/网络。

### 文件

创建：

- `https_relay_main.rs`
- `relay_config.rs`
- `relay_errors.rs`
- `relay_replay.rs`

修改：

- `Cargo.toml`：新增 `[[bin]] name = "codex-https-relay"`，入口 `https_relay_main.rs`。
- `Cargo.toml`：为 `tokio` 加入 `time`、`sync`（若实现所需）。

### BDD/RED 场景

- Given 正确签名，When 请求 `/v1/forward`，Then 进入注入的 fake forwarder。
- 错误 secret/key id、过期/未来 timestamp、重复 nonce、body digest 不匹配、控制头重复/缺失 → 拒绝。
- 上述拒绝场景 fake resolver/forwarder 调用次数为 `0`。
- `/v1/forward` 之外 404；外层非 POST 405。
- `/healthz` 只返回通用状态，不显示 key/config。

### GREEN

- current/previous key slot。
- `Mutex<HashMap<(key_id, nonce), expiry>>` 或等价有界 cache；每次请求清理过期项。
- 错误带内部固定 category，不带原始签名、secret、body 或完整 URL。

### 验证

```bash
cd /opt/codex-egress-relay
CARGO_BUILD_JOBS="$jobs" cargo test relay_auth
CARGO_BUILD_JOBS="$jobs" cargo clippy --all-targets -- -D warnings
```

### 提交建议

```text
feat: add authenticated HTTPS relay entrypoint
```

## Slice 3：动态 target 与 SSRF-safe resolver

### 文件

创建：

- `relay_target.rs`
- `safe_dns.rs`

### RED 场景

Target：

- 允许公共 `https://example.com/path?q=1`。
- 拒绝 HTTP、userinfo、fragment、自定义 port、过长 URL、非法 method。

IP policy：

- 拒绝 loopback、RFC1918、CGNAT、link-local、ULA、multicast、reserved、benchmark、documentation、metadata。
- IPv4-mapped IPv6 必须按映射 IPv4 再判定。
- DNS 返回 public+private 混合地址时整次拒绝。
- 验证通过的地址是 connector 实际使用的地址；禁止二次系统解析。

### GREEN

- 实现 `reqwest::dns::Resolve` 或等价 connector seam。
- resolver 返回同一次查询并已验证的 `SocketAddr`。
- client 显式 `.no_proxy()` 与 `.redirect(Policy::none())`。

### 验证

```bash
CARGO_BUILD_JOBS="$jobs" cargo test relay_target
CARGO_BUILD_JOBS="$jobs" cargo test safe_dns
```

### 提交建议

```text
feat: enforce public HTTPS targets with pinned safe DNS
```

## Slice 4：复用 TLS 指纹，完成 Rust 动态 HTTPS 转发

### 目标

保留旧 binary 行为，同时让新 binary 复用同一 rustls/aws-lc-rs 配置。

### 文件

修改：

- `tls.rs`：提取共享 TLS config/client builder；旧 `build_client(timeout_secs)` 行为保持测试锁定。
- `Cargo.toml`：如测试/streaming 需要，补最小依赖或 features。

创建：

- `relay_forward.rs`
- `relay_headers.rs`

### RED 场景

- 新 forwarder 只从已验签 canonical header block 重建并转发业务 headers，不转发 Cloudflare/外层控制/hop-by-hop headers。
- 动态 method/path/query/body 正确。
- 不调用 `identity.rs`，不二次修改 `client_metadata`。
- 上游 2xx/3xx/4xx/5xx 标记 `X-Codex-Relay-Result: upstream` 并保持 status。
- DNS/connect/TLS/header timeout 分类为 relay control error。
- reqwest 不跟随 redirect。
- `accept-encoding` 不被 reqwest 自动注入或改写；`content-encoding` 保留。
- 旧固定上游 binary 的现有 21 个测试继续通过。

### 超时实现

- 新 client 不使用覆盖完整 body 的短 total timeout。
- `connect_timeout` 只覆盖连接。
- `tokio::time::timeout` 覆盖 `send()` 到响应头。
- `read_timeout` 作为响应 body idle timeout。

### 验证

```bash
CARGO_BUILD_JOBS="$jobs" cargo test relay_forward
CARGO_BUILD_JOBS="$jobs" cargo test --all-targets
CARGO_BUILD_JOBS="$jobs" cargo clippy --all-targets -- -D warnings
```

### 提交建议

```text
feat: forward dynamic HTTPS targets with Codex TLS fingerprint
```

## Slice 5：Rust response streaming、容量和背压

### RED 场景

- fake upstream 先发送第一块，第二块由测试信号释放；Relay 客户端在第二块释放前已读到第一块。
- SSE 两个事件增量抵达。
- gzip bytes byte-for-byte 保持。
- HEAD/204 无非法 body。
- 非 SSE 超过 response cap 时中止流并记录固定错误分类。
- 并发 semaphore 满载时新请求拒绝，已在途请求不受影响。
- 下游断开时上游 stream 被 drop（单元/集成层可观察到 drop；真实边缘后续再验收）。

### 文件

修改：

- `relay_forward.rs`
- `relay_config.rs`
- `relay_errors.rs`

### 验证

```bash
CARGO_BUILD_JOBS="$jobs" cargo test relay_stream
CARGO_BUILD_JOBS="$jobs" cargo test --all-targets
```

### 提交建议

```text
feat: stream relay responses with bounded resources
```

## Slice 6：Worker Relay client 与 fail-closed 接线

### 文件

创建：

- `src/egress/relay.ts`
- `test/relay-egress.test.ts`

修改：

- `src/config.ts`
- `src/errors.ts`
- `src/index.ts`

### RED 场景

- Worker 使用固定 `EGRESS_RELAY_URL`，外层始终 POST `/v1/forward`。
- method/target/body digest/canonical header block/signature 符合 fixture。
- Relay config 缺失直接失败；`globalThis.fetch` 未被用于 target URL。
- Relay 不可达、auth error、timeout 映射稳定。
- `Result=upstream` 的真实上游 4xx/5xx 仍按上游响应返回，不误判为 Relay 故障。
- setup timeout 只覆盖响应头；响应头返回后 SSE 不被 timer 中断。
- 客户端取消传播到 Relay subrequest（Worker 测试层）。

### GREEN

- 使用 Cloudflare `crypto.subtle` HMAC-SHA256。
- nonce 使用 `crypto.getRandomValues`。
- target 使用 base64url UTF-8。
- 必需 config 缺失时 fail-closed。

### 验证

```bash
cd /opt/codex-worker-relay
./node_modules/.bin/vitest run test/relay-signing.test.ts test/relay-egress.test.ts
npm run typecheck
```

### 提交建议

```text
feat: route Worker egress through authenticated HTTPS relay
```

## Slice 7：Worker 客户端鉴权与 header hygiene

### 文件

创建：

- `src/ingress-auth.ts`
- `test/ingress-auth.test.ts`

修改：

- `src/headers.ts`
- `src/index.ts`
- `test/identity.test.ts`
- `test/worker.integration.test.ts`

### RED 场景

- 正确 `X-Codex-Relay-Token` 才允许目标请求。
- 缺失/错误 token → 401 且 Relay fetch 调用数为 0。
- token/control/CF/source-IP headers 不进入 canonical header block，不到上游。
- `Authorization` 与 Codex identity headers 进入 canonical header block 并被签名；外层 Relay 请求不依赖同名业务 header 的原样保留。
- 现有 `client_metadata` 投影行为不回归。

### GREEN

- token 恒定时间比较。
- 入口 token 与 Worker→Relay HMAC secret 分离。
- 不增加 URL/query secret 兼容路径。

### 验证

```bash
./node_modules/.bin/vitest run test/ingress-auth.test.ts test/identity.test.ts test/worker.integration.test.ts
npm run typecheck
```

### 提交建议

```text
feat: authenticate relay clients and strip source headers
```

## Slice 8：安全重定向重写

### 文件

创建：

- `src/redirect.ts`
- `test/redirect.test.ts`

修改：

- `src/index.ts` 或统一 response projection owner。

### RED 场景

- 相对、绝对 HTTPS Location 重写为 Worker origin 的动态 target path。
- query/path/percent encoding 保留。
- HTTP、userinfo、自定义 port、非法 hostname → `502 invalid_upstream_redirect`。
- 自动跟随后第二跳仍调用 Relay，不调用 direct target fetch。

### 提交建议

```text
feat: keep upstream redirects on the VPS relay path
```

## Slice 9：删除旧生产出口，统一单一真相源

只有 Slice 6–8 全绿后执行。

### 删除

- `src/egress/direct.ts`
- `src/egress/proxy.ts`
- `src/egress/sockets.ts`
- `src/egress/socks5.ts`
- `src/egress/http1.ts`
- 对应 direct/SOCKS5/HTTP1 测试（先把仍有价值的 header/stream/error 场景迁到 Relay 测试，再删除）。

### 修改

- `src/index.ts`：唯一 egress 调用 `sendViaRelay()`。
- `src/config.ts`：删除 `EGRESS_PROXY_URL` 和 tunnel timeout。
- `README.md`、`.env.example`（若创建）与 CI 文档。

### 扫描

```bash
# 使用 search_files 搜索，不用 shell grep
# 目标关键词：sendDirect, sendViaProxy, EGRESS_PROXY_URL,
# cloudflare:sockets, startTls, socks5, DEFAULT_TUNNEL_TIMEOUT_MS
```

任何可达旧分支或 stale 文档都必须删除，不加默认关闭的兼容 flag。

### 验证

```bash
npm run check
git diff --check
```

### 提交建议

```text
refactor: make HTTPS relay the only Worker egress
```

## Slice 10：Rust 部署资产（不激活）

### 文件

创建：

- `systemd/codex-https-relay.service`
- `https-relay.env.example`
- `docs/https-relay-runbook.md`

### unit 要求

- `ExecStart=/opt/codex-egress-relay/target/release/codex-https-relay`
- `EnvironmentFile=/opt/codex-egress-relay/https-relay.env`
- 监听 loopback 高位端口；不需要 capability。
- 复用现有 unit 的 crash-loop brake、resource ceilings、filesystem/privilege sandbox。
- 不设置虚假 `WatchdogSec`。
- 仅 `AF_INET AF_INET6`。
- secret 文件 `0600`，目录不新增无必要 writable path。

### 候选构建

```bash
jobs=$(( ($(nproc) + 1) / 2 ))
CARGO_BUILD_JOBS="$jobs" cargo build --release --bin codex-https-relay
```

注意：只构建新 binary，不停止/重启现有服务。

### 本机只读验收

- `systemd-analyze verify systemd/codex-https-relay.service`
- 使用临时非敏感测试 key 启动在不同本地端口。
- `/healthz` 正常。
- HMAC 失败无 DNS/forward。
- 停止临时进程并清理 env/log。

### 提交建议

```text
ops: add hardened HTTPS relay service assets
```

## Slice 11：Cloudflare Worker 配置与部署文档（不部署）

### 修改

- `wrangler.toml`：只加入非 secret 变量占位/环境结构；真实 secret 不提交。
- `README.md`：客户端 token、Relay URL、fail-closed、限制、安全模型。
- CI：继续 `npm ci && npm run check`；增加协议 fixture 漂移检查（若实现为脚本）。

### Secret 写入方式

必须走 stdin 或 CLI 安全输入，禁止命令行参数/日志回显。至少包括：

- `INGRESS_AUTH_TOKEN`
- `EGRESS_RELAY_SECRET`

`EGRESS_RELAY_URL` 与 key id 可作为环境变量；若 URL 含任何敏感信息则改为 secret。

## Slice 12：真实 VPS/Tunnel 候选部署（高风险，需用户明确授权）

### 前置确认

- VPS 身份/IP、SSH 入口和不切断当前远程链路的回滚方式。
- Relay public hostname 与 Cloudflare account/zone。
- cloudflared 现状、备份和版本。
- 现有服务/端口冲突。
- Secret 生成、保管和轮换方式。

### 部署顺序

1. VPS 备份现有 unit/env，最多保留最近两份；旧服务保持运行。
2. 安装新 binary、`0600` env、new unit；仅监听 `127.0.0.1:<proposed-port>`。
3. 本机 HMAC canary 验证。
4. 新建独立 Tunnel ingress/public hostname，仅指向新 loopback service。
5. 从 Cloudflare 外部发起合法/非法 HMAC 请求，验证 auth、重放、SSRF。
6. 不修改生产 Worker；先部署独立 preview Worker 和独立 secrets。

### 回滚

- 删除/禁用新 preview Worker route/version。
- 删除新 Tunnel hostname route。
- `systemctl disable --now codex-https-relay`（由用户授权后执行）。
- 恢复 unit/env 备份或删除新 unit。
- 旧 `codex-egress-relay` 从始至终不停止、不重启。

## Slice 13：真实端到端验收

必须证明：

```text
客户端
→ preview Worker
→ public HTTPS Relay hostname
→ Cloudflare Tunnel
→ VPS loopback Rust Relay
→ 动态公共 HTTPS upstream
→ VPS
→ Worker
→ 客户端
```

### 正向矩阵

- 三个未预配置、不同组织的公共 hostname。
- 一个受控 echo 上游：检查 method/path/query/body/Authorization/Codex headers，确认无 CF/source-IP/control headers。
- 一个出口 IP endpoint：确认来源是 VPS 公网 IP。
- JSON POST。
- gzip/identity response。
- SSE：首事件、第二事件、正常关闭；记录首事件时延而非只看总结果。
- 上游 204、3xx、4xx、5xx。
- 3xx 自动跟随后仍显示 VPS 出口。

### 负向矩阵

- 错误入口 token。
- Relay secret/key 错误。
- timestamp 过期/未来、nonce replay。
- Relay service 停止或 Tunnel route 不可用。
- private/loopback/link-local/metadata target。
- DNS mixed-address fixture。
- body 超限、URL 超限、非法 method。
- 上游 DNS/TLS/connect/header/read-idle timeout。
- concurrency 满载。

所有 Relay 故障场景必须验证 target endpoint 没收到 direct Cloudflare 请求。

### 最终门禁

```bash
cd /opt/codex-worker-relay
npm run check
git status --short
git diff --check

cd /opt/codex-egress-relay
CARGO_BUILD_JOBS="$jobs" cargo fmt --all -- --check
CARGO_BUILD_JOBS="$jobs" cargo clippy --all-targets -- -D warnings
CARGO_BUILD_JOBS="$jobs" cargo test --all-targets
git status --short
git diff --check
```

并执行：

- 全仓库 secret/IP/hostname 扫描，排除 `.git`、`node_modules`、`target`、`dist`。
- Cloudflare control plane 资源清单核对。
- VPS `systemctl status`、loopback listener、cloudflared route、服务日志脱敏核对。
- 删除临时 Worker、fixtures、tail、测试 secret、日志、body、state 文件。

## Slice 14：生产切换与回滚演练（高风险，需再次明确授权）

### 切换

- 先发布已通过验收的 Worker version，但不立即把所有 route 流量切过去；使用 preview/custom canary route。
- 小流量真实请求验证后再切正式 route。
- 生产 config 缺少 Relay 时必须拒绝请求。
- 切换后再次验证出口 IP、SSE、错误映射和日志。

### 回滚

- Worker 回滚到上一已知版本/route。
- 新 Rust Relay 可停止；旧 Rust oracle 不受影响。
- Tunnel route 可独立移除。
- 回滚后验证原入口实际行为，不只检查命令成功。

## 完成定义

只有以下全部成立，才可宣称生产可用：

1. 两仓库全部门禁通过。
2. Worker 生产代码只有 HTTPS Relay 一条 egress 路径。
3. 动态 hostname 的真实请求与 SSE 均从 VPS 出口成功。
4. Relay 不可用时无 direct fallback。
5. HMAC/replay/SSRF/入口鉴权/限额通过负向验收。
6. redirect 不会把客户端带到直连上游。
7. 无 secret 泄露，日志脱敏。
8. 临时资源清理，回滚已实际演练。
9. 原 Rust 服务仍是可用 oracle，直到用户另行决定退役。
