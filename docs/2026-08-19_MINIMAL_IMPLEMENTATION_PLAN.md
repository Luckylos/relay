# Codex Worker Relay 最小实现计划

> **归档（2026-08-21）：** 本文件是历史过程记录，不描述当前架构。
> 计划已实施完成；`codex-egress-relay` 本机出口链路已退役，身份投影现由 Worker 单一持有。当前架构见 `README.md` 与 `egress-relay/README.md`；线协议已前进到 v2，差异见 `docs/relay-protocol-v2-delta.md`。

> **项目路径：** `/opt/codex-worker-relay`  
> **计划文件：** `/opt/codex-worker-relay/.hermes/plans/2026-08-19_235214_MINIMAL_IMPLEMENTATION_PLAN.md`  
> **参考实现：** `/opt/codex-egress-relay`，只读基线 `6f0d58b80f21`  
> **约束：** 不修改、不构建覆盖、不提交到原项目；新项目独立初始化、测试和提交。

## 1. 目标

新建一个独立的 Cloudflare Workers 项目，实现以下最小可用能力：

```text
客户端
  → https://<worker-domain>/<目标域名>/<目标路径>?<query>
  → Codex Header/JSON Body 身份投影
  → 全局出站选择
      ├─ 未配置 EGRESS_PROXY_URL：Cloudflare fetch 直连
      └─ 已配置 EGRESS_PROXY_URL：固定 HTTP 或 SOCKS5 代理
  → 任意 HTTPS 目标域名
  → 状态码、响应 Header、SSE/Body 流式返回
```

示例：

```text
https://relay.example.com/api.example.com/v1/responses?stream=true
```

解析为：

```text
https://api.example.com/v1/responses?stream=true
```

## 2. 已冻结的产品契约

### 2.1 动态目标

- 第一个路径段是目标域名。
- 第一个路径段之后的 path 原样拼接到目标域名。
- 原始 query 原样保留。
- 上游协议在 MVP 固定为 `https://`。
- 不建立域名路由表。
- 不设置域名允许列表。
- 不为每个域名单独配置出站。
- 任意格式有效的域名都走同一套处理链。

### 2.2 全局可选出站

只支持一个全局可选配置：

```text
EGRESS_PROXY_URL
```

行为：

```text
EGRESS_PROXY_URL 未设置
  → 所有目标使用 Cloudflare fetch

EGRESS_PROXY_URL=http://[user:pass@]host:port
  → 所有目标使用该固定 HTTP CONNECT 代理

EGRESS_PROXY_URL=socks5://[user:pass@]host:port
  → 所有目标使用该固定 SOCKS5 代理
```

- SOCKS5 使用域名型 CONNECT（ATYP=DOMAIN），让代理节点解析目标域名。
- 配置了代理但连接、鉴权或隧道失败时返回 `502/504`。
- 代理失败不得静默回落到 Cloudflare 直连。
- HTTP/SOCKS 凭据只允许来自 Worker Secret，不得出现在日志、健康检查或错误响应中。

### 2.3 Codex 请求身份

以 `/opt/codex-egress-relay/identity.rs` 为行为 oracle，移植而不是重新发明规则：

- 保留真实 Codex 客户端已经携带的身份值。
- 非 Codex 客户端生成一致的：
  - `user-agent`
  - `originator`
  - `session-id`
  - `thread-id`
  - `x-client-request-id`
  - `x-codex-window-id`
  - `x-codex-installation-id`
  - `x-codex-beta-features`
  - `x-codex-turn-metadata`
  - `accept-encoding`
- Header 和 Body 的 installation/session/thread/window/turn 值必须来自同一个 `ResolvedIdentity`。
- `Authorization`、`Content-Type` 等非身份 Header 保持透传。
- 删除请求侧 hop-by-hop Header。
- 仅当 `Content-Type` 包含 `application/json`、顶层是 object 且不存在 `client_metadata` 时注入。
- 已有 `client_metadata` 的 Body 必须字节级保持不变。
- 非 JSON、坏 JSON、数组或标量 Body 不修改。

### 2.4 响应行为

- 返回上游原始状态码。
- 删除响应侧 hop-by-hop Header。
- 不解压响应内容。
- SSE 必须边到边发送，不得等待完整上游响应结束后才返回。
- 两种出站模式对外错误 envelope 一致：

```json
{
  "error": {
    "message": "...",
    "type": "..."
  }
}
```

### 2.5 MVP 明确不做

以下项目进入后续安全/增强阶段，不阻塞本轮功能实现：

- 域名允许列表。
- Worker 入口鉴权。
- 限流、配额和滥用治理。
- SSRF/私网目标策略。
- 每域名/每渠道出站策略。
- 多代理池、负载均衡和健康切换。
- 代理失败后自动直连。
- Durable Objects、KV、D1 或管理后台。
- 任意上游协议、显式端口和嵌套完整 URL。
- 复刻 Rust `aws-lc-rs` 的 JA4/HTTP2 指纹；Worker 出站 TLS 由 Cloudflare 运行时控制。

秘密不泄露、错误不回显代理凭据属于基础正确性，不延期。

## 3. 领域边界

### 3.1 核心领域对象

```ts
interface TargetRequest {
  hostname: string;
  pathname: string;
  search: string;
  url: URL;
}

interface ResolvedIdentity {
  userAgent: string;
  originator: string;
  sessionId: string;
  threadId: string;
  requestId: string;
  windowId: string;
  installationId: string;
  betaFeatures: string;
  turnId: string;
  turnStartedAtUnixMs: number;
  clientTurnMetadata?: string;
}

type EgressConfig =
  | { type: "direct" }
  | { type: "http"; hostname: string; port: number; username?: string; password?: string }
  | { type: "socks5"; hostname: string; port: number; username?: string; password?: string };
```

### 3.2 单一规则所有者

- `parseTarget()`：唯一负责路径到 HTTPS 目标 URL 的转换。
- `resolveIdentity()`：唯一负责身份决策。
- `projectIdentity()`：唯一负责 Header 和 Body 两层投影。
- `parseEgressConfig()`：唯一负责全局 direct/http/socks5 选择。
- `sendDirect()` / `sendViaProxy()`：出站适配器；不得复制身份规则。
- `proxyHandler()`：只编排，不自行实现第二份域名、身份或代理选择逻辑。

## 4. 新项目结构

```text
/opt/codex-worker-relay/
├── .github/
│   └── workflows/
│       └── ci.yml
├── .hermes/
│   └── plans/
│       └── 2026-08-19_235214_MINIMAL_IMPLEMENTATION_PLAN.md
├── src/
│   ├── index.ts
│   ├── config.ts
│   ├── target.ts
│   ├── identity.ts
│   ├── headers.ts
│   ├── errors.ts
│   └── egress/
│       ├── index.ts
│       ├── direct.ts
│       ├── proxy.ts
│       ├── http-connect.ts
│       ├── socks5.ts
│       └── http1.ts
├── test/
│   ├── target.test.ts
│   ├── identity.test.ts
│   ├── direct-egress.test.ts
│   ├── proxy-config.test.ts
│   ├── http-connect.test.ts
│   ├── socks5.test.ts
│   ├── http1.test.ts
│   └── worker.integration.test.ts
├── test-fixtures/
│   └── capability-worker.ts
├── .gitignore
├── package.json
├── package-lock.json
├── tsconfig.json
├── vitest.config.ts
├── wrangler.toml
└── README.md
```

`test-fixtures/capability-worker.ts` 只用于验证 Cloudflare 真实运行时能否在 HTTP CONNECT/SOCKS5 隧道上再包装目标 TLS；最终生产入口不得暴露探针接口。

## 5. 配置面

### 5.1 `wrangler.toml`

最小配置：

```toml
name = "codex-worker-relay"
main = "src/index.ts"
compatibility_date = "2026-08-19"
compatibility_flags = ["nodejs_compat"]
```

不在仓库中写代理 URL 或凭据。

### 5.2 Worker bindings

```ts
interface Env {
  EGRESS_PROXY_URL?: string;
  CODEX_PROXY_UA_VERSION?: string;
  CODEX_PROXY_ORIGINATOR?: string;
  CODEX_PROXY_UA_OS?: string;
  CODEX_PROXY_UA_TERMINAL?: string;
  CODEX_PROXY_USER_AGENT?: string;
  CODEX_PROXY_BETA_FEATURES?: string;
  CODEX_PROXY_INSTALLATION_ID?: string;
  CODEX_PROXY_ACCEPT_ENCODING?: string;
  CODEX_PROXY_TIMEOUT?: string;
  CODEX_PROXY_MAX_BODY_BYTES?: string;
}
```

默认值与 Rust 参考实现一致：

- UA version：`0.145.0`
- originator：`codex-tui`
- OS：`Debian 12.0.0; x86_64`
- terminal：`unknown`
- beta features：`remote_compaction_v2`
- accept encoding：`gzip, deflate`
- timeout：`120s`
- max body：`10485760` bytes

`CODEX_PROXY_INSTALLATION_ID` 未设置时可在 Worker isolate 内生成一次 UUID；正式使用建议显式设置稳定值，但不是 MVP 启动前提。

## 6. 关键技术决策

### 6.1 直连模式

使用标准 Worker `fetch()`：

```ts
fetch(target.url, {
  method,
  headers,
  body,
  redirect: "manual",
});
```

- `redirect: "manual"` 保证 direct 和 proxy 模式均把上游重定向原样返回，不产生两套重定向语义。
- Body 在身份注入前受 `CODEX_PROXY_MAX_BODY_BYTES` 限制。
- 返回 `Response(upstream.body, ...)`，保持 Web Stream。

### 6.2 HTTP/SOCKS5 模式

Cloudflare `fetch()` 没有通用 `proxy` 参数，MVP 采用 `nodejs_compat` 的 `node:net` / `node:tls`：

1. TCP 连接固定代理节点。
2. HTTP proxy：发送 CONNECT 并要求 2xx。
3. SOCKS5 proxy：完成 method negotiation、可选 RFC 1929 用户名/密码鉴权、DOMAIN CONNECT。
4. 在已经建立的 tunnel socket 上调用 `tls.connect({ socket, servername, ALPNProtocols: ["http/1.1"] })`。
5. 通过该 TLS socket 发送 HTTP/1.1 请求。
6. 解析 status line 与 Header。
7. 将定长、connection-close 或 chunked Body 转换为 Web `ReadableStream`。
8. 上游 socket 在响应流结束、取消或错误时关闭。

只协商 HTTP/1.1，避免在 MVP 中同时实现 HTTP/2 framing。

### 6.3 能力门禁

官方文档确认 Workers 提供 `node:net`、`node:tls.connect` 和 TCP socket，但“在已建立的代理隧道 socket 上进行目标 TLS 并持续桥接为 Response stream”必须在真实 Cloudflare Worker 运行时验证。

因此第一个远程验收必须同时证明：

```text
HTTP CONNECT → target TLS → GET → 收到目标 marker
SOCKS5 CONNECT → target TLS → GET → 收到目标 marker
```

若 Cloudflare 运行时不支持 `tls.connect({ socket })` 或无法稳定桥接响应流：

- 停止纯 Worker 的代理分支实现。
- direct 模式不能冒充完整需求完成。
- 保留已经通过的动态路由、身份和 direct 代码。
- 单独报告代理分支阻塞，再决定 Cloudflare Container 或外部 egress helper；本计划不擅自引入该架构。

## 7. BDD 验收场景

### 场景 A：任意域名直连，无路由表

```text
Given EGRESS_PROXY_URL 未设置
And Worker 没有任何域名映射配置
When POST /first.example/v1/responses?stream=true
Then 上游目标为 https://first.example/v1/responses?stream=true
And 使用 direct fetch

When 再请求 /second.example/v1/models
Then 上游目标为 https://second.example/v1/models
And 无需新增配置
```

### 场景 B：全局 HTTP 代理

```text
Given EGRESS_PROXY_URL=http://user:pass@proxy.example:8080
When 请求任意有效目标域名
Then Worker 对 proxy.example:8080 建立 HTTP CONNECT
And CONNECT authority 是 <动态目标>:443
And 所有目标共用这一个代理配置
```

### 场景 C：全局 SOCKS5 代理

```text
Given EGRESS_PROXY_URL=socks5://user:pass@proxy.example:1080
When 请求任意有效目标域名
Then Worker 完成 SOCKS5 用户名密码协商
And CONNECT 使用 ATYP=DOMAIN
And 代理收到动态目标域名及端口 443
```

### 场景 D：代理失败时关闭失败

```text
Given 已配置 HTTP 或 SOCKS5 代理
And 代理拒绝、超时或鉴权失败
When 发起请求
Then Worker 返回 502 或 504 JSON
And 不调用 direct fetch
And 响应及日志不包含代理 URL、用户名或密码
```

### 场景 E：身份 Header 与 Body 一致

```text
Given 非 Codex 客户端发送 application/json object
When Worker 转发请求
Then 上游收到完整 Codex 身份 Header
And client_metadata 被注入
And Header 与 Body 的 installation/session/thread/window/turn 值一致
And Authorization 保持不变
```

### 场景 F：已有真实身份不被破坏

```text
Given 请求已经包含真实 Codex Header 和 client_metadata
When Worker 转发请求
Then 现有身份值被保留
And Body 字节级不变
And 不生成第二份身份 Header
```

### 场景 G：SSE 真流式返回

```text
Given 测试上游先发送第一条 SSE event，延迟后再发送第二条
When 请求经 direct、HTTP proxy、SOCKS5 proxy 三种模式分别转发
Then 客户端在第二条产生前已经读到第一条
And Body 未被整体缓冲
```

### 场景 H：路径输入边界

```text
Given 请求路径缺少目标域名或首段不是合法 DNS hostname
When Worker 解析请求
Then 返回 400 invalid_target
And 不发起任何出站连接
```

该验证仅是语法边界，不是域名允许列表。

## 8. TDD 实施任务

每个任务严格执行：先写一个失败测试并观察 RED，再写最小实现到 GREEN，最后重构；不得先写生产代码。

### Task 1：建立独立项目与本地门禁

**新增文件：**

- `/opt/codex-worker-relay/package.json`
- `/opt/codex-worker-relay/package-lock.json`
- `/opt/codex-worker-relay/tsconfig.json`
- `/opt/codex-worker-relay/vitest.config.ts`
- `/opt/codex-worker-relay/wrangler.toml`
- `/opt/codex-worker-relay/.gitignore`

**步骤：**

1. 在 `/opt/codex-worker-relay` 初始化独立 Git 仓库，分支 `main`。
2. 使用项目本地 `node_modules`，不安装或替换全局 npm 包。
3. 添加 TypeScript、Vitest、Cloudflare Workers test pool 和 Wrangler 开发依赖。
4. 定义脚本：

```json
{
  "scripts": {
    "test": "vitest run",
    "test:watch": "vitest",
    "typecheck": "tsc --noEmit",
    "build": "wrangler deploy --dry-run --outdir dist",
    "check": "npm run typecheck && npm test && npm run build"
  }
}
```

5. 运行 `npm run check`，建立空项目绿色基线。
6. 本地提交，不推送远端。

### Task 2：动态目标解析

**测试先行：** `test/target.test.ts`

RED 用例：

- `/api.example.com` → `https://api.example.com/`
- `/api.example.com/v1/responses?x=1` → path/query 正确。
- 两个不同域名均无需配置即可解析。
- 空路径、只有 `/`、含 scheme、userinfo、端口或非法 hostname 返回 `invalid_target`。
- encoded slash 不得改变首段边界。

**实现：** `src/target.ts`

- 单次提取首段。
- 固定 HTTPS 与 443。
- 剩余 pathname 和 search 保留。
- 不读取域名配置表。

**验证：**

```bash
npm test -- target.test.ts
npm run typecheck
```

### Task 3：移植身份单一真相源

**测试先行：** `test/identity.test.ts`

从 Rust oracle 逐项建立等价测试：

- 非 Codex 客户端完整身份合成。
- session/thread/request/window 一致。
- genuine Codex UA/originator 保留。
- `session-id` / `session_id` 与 `thread-id` / `thread_id` 去重。
- 非身份 Header 透传。
- hop-by-hop Header 删除。
- JSON object 注入 `client_metadata`。
- Header/Body installation ID 一致。
- 已有 metadata 字节不变。
- 非 JSON、坏 JSON、array、scalar 不变。

**实现：**

- `src/config.ts`
- `src/identity.ts`
- `src/headers.ts`

时间和 UUID 通过可注入依赖或测试工厂固定，避免测试依赖真实时钟和随机数。

### Task 4：完成 direct Worker 垂直切片

**测试先行：** `test/direct-egress.test.ts`、`test/worker.integration.test.ts`

完整走 `SELF.fetch()`：

```text
Worker request
→ target parser
→ identity resolution/projection
→ mocked fetch upstream
→ streamed Response
```

RED 用例：

- 动态 host/path/query 转发。
- method、Authorization、Content-Type 透传。
- Body metadata 注入。
- 上游状态码返回。
- 响应 hop-by-hop Header 删除。
- 第一段 SSE 在第二段产生前可读。
- Body 超过上限返回 413。
- 缺少目标返回 400。

**实现：**

- `src/egress/direct.ts`
- `src/errors.ts`
- `src/index.ts`

### Task 5：真实 Worker 代理隧道能力 Spike

**文件：** `test-fixtures/capability-worker.ts`

该任务在写完整代理模块前执行，以免先完成一套运行时不支持的实现。

**必须验证：**

1. `node:net` 可连接公开 HTTP/SOCKS5 测试节点。
2. 可在完成 CONNECT 后把已有 socket 传给 `tls.connect({ socket, servername })`。
3. 可发送 HTTP/1.1 请求并读取目标 marker。
4. TLS 证书校验和 SNI 使用目标域名而不是代理域名。
5. socket 字节可桥接为 Worker `ReadableStream`。

**验收方式：**

- 使用临时 preview Worker，不绑定正式自定义域名。
- 使用受控 HTTPS marker origin。
- HTTP 与 SOCKS5 各执行正向测试。
- 错误密码执行负向测试并确认被拒绝。
- 验收后删除临时 Worker 和探针入口。

**停止条件：** 任一核心能力不成立，则停止 proxy 分支，不以 direct 模式冒充完整交付。

### Task 6：全局代理配置解析

**测试先行：** `test/proxy-config.test.ts`

RED 用例：

- 未设置 → `direct`。
- `http://host:port` → HTTP profile。
- `socks5://host:port` → SOCKS5 profile。
- 可选 URL 编码用户名密码正确解析。
- 缺失 host、非法端口、未知 scheme → `proxy_config_error`。
- error/debug string 不含用户名密码。
- 目标域名变化不改变全局 egress profile。

**实现：** `src/egress/index.ts`、`src/config.ts`

### Task 7：HTTP CONNECT

**测试先行：** `test/http-connect.test.ts`

使用内存 socket fixture 验证：

- CONNECT request authority 正确。
- `Host` 正确。
- 有凭据时发送 `Proxy-Authorization` Header，并验证其为 Basic 认证格式。
- 无凭据时不发送代理认证 Header。
- 2xx 接受，407 映射代理鉴权失败，其他非 2xx 映射 502。
- Header 上限与超时生效。
- 错误不回显 credential。

**实现：** `src/egress/http-connect.ts`

### Task 8：SOCKS5

**测试先行：** `test/socks5.test.ts`

逐字节验证：

- 无鉴权 method negotiation。
- username/password RFC 1929 negotiation。
- 使用 ATYP=DOMAIN，不在 Worker 侧预解析目标域名。
- 端口固定 443，大端序编码。
- proxy reject code 分类为 502。
- 鉴权失败不重试 direct。
- 截断响应、未知 method、超长 credentials 失败关闭。

**实现：** `src/egress/socks5.ts`

### Task 9：TLS 隧道上的 HTTP/1.1 编解码与 SSE

**测试先行：** `test/http1.test.ts`

RED 用例：

- 正确序列化 method/path/query/Host/Header/Content-Length/Body。
- 不发送 hop-by-hop Header。
- 解析 status line 和重复 Header。
- content-length Body 流式读取。
- connection-close Body 流式读取。
- chunked Body 解帧后流式返回。
- chunk extension 与 trailer 被正确消费。
- 第一块 SSE 不等待连接结束。
- caller cancel 时关闭 socket。
- malformed response/header overflow/timeout 映射 502/504。

**实现：** `src/egress/http1.ts`、`src/egress/proxy.ts`

该模块不做 gzip/br 解压，只移除 HTTP/1.1 framing。

### Task 10：统一三种出站的 Worker 集成验收

**测试：** `test/worker.integration.test.ts`

同一组行为分别跑：

- direct
- HTTP proxy
- SOCKS5 proxy

必须证明：

- 三种模式使用同一个 target parser 和 identity owner。
- arbitrary domain 无配置即可工作。
- proxy 配置是全局单项，不存在 per-domain egress。
- Header/Body 行为一致。
- status/Header/SSE 行为一致。
- 代理失败时没有 direct fetch 调用。

### Task 11：文档与 CI

**新增/修改：**

- `README.md`
- `.github/workflows/ci.yml`

README 必须包含：

- URL 形态与三个完整示例。
- `EGRESS_PROXY_URL` 未设置、HTTP、SOCKS5 三种模式。
- `wrangler secret put EGRESS_PROXY_URL`，不展示真实 secret。
- 配置了代理后 fail-closed 的语义。
- 身份 Header/Body 行为。
- SSE 与 10 MiB Body 边界。
- Worker 版不保证 Rust JA4/H2 指纹。
- 当前 MVP 无入口鉴权/allowlist 的事实，但不在本轮实现安全功能。

CI：

```bash
npm ci
npm run check
```

### Task 12：候选构建与真实目标层验证

在不绑定生产域名的 preview/temporary Worker 上：

1. direct 模式请求受控 echo origin，验证其看到的 path/query/Header/Body。
2. direct 模式请求 SSE origin，验证首事件提前到达。
3. HTTP proxy 模式验证目标看到的出口 IP 是 HTTP proxy 出口。
4. SOCKS5 模式验证目标看到的出口 IP 是 SOCKS5 proxy 出口。
5. 两种代理分别使用错误凭据，确认 502 且没有 Cloudflare 直连请求。
6. 运行一个非 Codex 客户端请求，验证上游实际收到 `client_metadata.x-codex-installation-id`。
7. 运行一个已有 metadata 的请求，比较上游收到的 Body 与输入字节。
8. `npm run check` 全绿。
9. `git diff --check` 无错误，工作树只包含计划内文件。
10. 删除 capability spike Worker 和所有临时 secret/preview 资源。

正式自定义域名、入口鉴权和公网长期暴露不属于本计划的激活步骤。

## 9. 提交切片

仅本地提交，不推送远端：

1. `chore: scaffold standalone Cloudflare Worker project`
2. `feat: parse dynamic HTTPS targets without route config`
3. `feat: port coherent Codex request identity projection`
4. `feat: add direct Cloudflare egress with streamed responses`
5. `test: prove proxy tunnel TLS capability on Workers runtime`
6. `feat: add global HTTP CONNECT egress`
7. `feat: add global SOCKS5 egress`
8. `feat: stream tunneled HTTP responses and SSE`
9. `test: verify direct HTTP and SOCKS egress end to end`
10. `docs: document Worker usage configuration and limits`

每个提交前运行对应 focused test；每个垂直切片完成后运行 `npm run check`。

## 10. 回滚

- 原项目完全不改，因此不存在原服务回滚或重启边界。
- 新项目每个切片单独提交；失败时回退到上一个绿色提交。
- capability spike 失败时删除临时 Worker/secret，保留本地测试和证据，不部署残缺代理分支。
- preview 验收失败时不绑定正式域名，不修改 cloudflared/Tunnel 配置。
- 新项目若整体放弃，可直接归档或删除 `/opt/codex-worker-relay`；不会影响当前运行的 `codex-egress-relay` systemd 服务。

## 11. 完成定义

只有同时满足以下条件才称为“最小需求实现完成”：

- `/opt/codex-egress-relay` 保持原 HEAD、原工作树和原运行状态。
- 新项目拥有独立源码、依赖锁文件、测试、CI 和 README。
- arbitrary domain 动态路径无需域名配置即可转发。
- `EGRESS_PROXY_URL` 未设置时真实走 Cloudflare direct。
- 设置 HTTP proxy 时真实从该代理出口到达目标。
- 设置 SOCKS5 proxy 时真实从该代理出口到达目标。
- 代理失败真实 fail-closed，无 direct fallback。
- Header 与 Body 身份规则与 Rust oracle 一致。
- direct/HTTP/SOCKS 三种模式都通过 SSE 提前到达验证。
- `npm run check` 通过。
- 临时探针和 Cloudflare preview 资源已清理。

若缺少可供 Cloudflare 访问的 HTTP/SOCKS5 测试节点或 Cloudflare 账号授权，则相应真实出站场景必须标记为 `deferred`，不能用单元测试代替并宣称完成。
