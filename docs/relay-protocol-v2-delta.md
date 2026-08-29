# Relay 线协议 v2 增量

本文只描述 v2 与 v1 的差异，以及迁移窗口内两代并存的规则。v1 的完整语义仍以
`docs/https-relay-design-v1.md` 为准——那份文档是 v1 的准确描述，不是过期描述。

v1 **未退役**：relay 同时接受 v1 与 v2。两个 ingress 与 relay 各自独立部署，任何
时刻都可能是一代新一代旧，所以两代必须同时可用。

## 1. 差异清单

只有两件事变了：控制头命名空间，和签名域分隔符。

| 项 | v1 | v2 |
|---|---|---|
| 控制头前缀 | `x-codex-relay-` | `x-egress-relay-` |
| 签名域分隔符（canonical request 第 1 行） | `codex-relay-v1` | `egress-relay-v2` |
| `x-*-relay-version` 头值 | `1` | `2` |

改名的理由：`x-codex-relay-` 描述的是项目来源，而现在同一条出口同时承载 Codex 与
Claude 两个 ingress；`x-egress-relay-` 描述的是这一跳本身。

canonical request 的其余部分逐字节不变：字段顺序、大小写规范化、header 值只折叠
SPACE/TAB、ASCII 排序、base64url 无 padding、body SHA-256、nonce 16 字节、
timestamp 语义全部照旧。

```text
<domain-separator>          # 唯一变化的一行
<key-id>
<timestamp>
<nonce>
<METHOD>
<base64url-target>
<body-sha256>
<base64url-canonical-header-block>
```

因此 v1 与 v2 的 fixture 只应在三个字段上不同：`version`、`canonical_request`
第 1 行、`signature`。

```text
protocol/relay-protocol-v1.json    冻结，不得再改一个字节
protocol/relay-protocol-v2.json    当前代
```

每代 fixture 在三个 subtree 各有一份逐字节相同的副本
（`egress-relay/tests/fixtures/`、`codex-ingress/test/fixtures/`、
`claude-ingress/test/fixtures/`），因为每个 subtree 必须能独立抽出来跑测试，不能在
构建期跨目录读 `protocol/`。`protocol/conformance.py` 负责证明副本与 canonical 一致，
并把每个基础向量在 v1 与 v2 下各跑一次，覆盖 Python / Rust / TS-Codex / TS-Claude
四个实现。

## 2. 签名域为什么必须版本化而不是原地改名

域分隔符是 canonical request 的第 1 行，改它会改变每一个签名。原地把
`codex-relay-v1` 改成新名字，等于让所有已部署的 v1 签名立刻验不过——那不是重命名，
是一次无兼容窗口的协议断裂。

所以三个实现都保留两个常量并按 version 查表：

```text
egress-relay/src/protocol/signing.rs    DOMAIN_SEPARATOR_V1 / DOMAIN_SEPARATOR_V2 / CURRENT_VERSION = 2
*/src/relay/protocol.ts                 同名 export，同值
egress-relay/scripts/relay_probe.py     DOMAIN_SEPARATORS = {1: ..., 2: ...}
```

未知 version 必须显式拒绝（Rust `ProtocolError::UnsupportedVersion`、TS
`unsupported_version`、probe `SystemExit`），不得回落到 v2。否则将来的 v3 会被错误地
按 v2 域验签，把一次协议错误变成一次静默的签名伪造面。

`build_canonical_request()` / `buildCanonicalRequest()` 在校验其他字段**之前**解析
域分隔符，所以不支持的代恒定报 `unsupported_version`，而不是报后面某个字段无效。

## 3. relay 侧：请求单代读取

`egress-relay/src/app/relay.rs` 保留两个前缀常量，并对每个请求先判定一次代：

- 只出现 `x-egress-relay-*` → `Current`
- 只出现 `x-codex-relay-*` → `Legacy`
- **两者同时出现** → `400 relay_duplicate_control`
- 一个控制头都没有 → 按 `Legacy` 处理，随后必然因缺字段被拒

代只判定一次，之后 envelope 的每个字段都必须从同一代读取。禁止逐字段 fallback：那会
允许把两代请求拼在一起，攻击者可以用一代的字段覆盖另一代的字段。

混代直接拒绝而不是择一解析，也意味着 ingress 绝不能同时发两套 envelope 头——那不是
兼容，那是一次全量 outage。ingress 只发当前代。

## 4. relay 侧：响应双代标记

relay 在**每个**响应上同时写两代归因头，值相同，request id 每个响应只生成一次：

```text
x-egress-relay-result      upstream | error
x-egress-relay-error       <machine-code>    # 仅 error
x-egress-relay-request-id  <opaque-id>
x-codex-relay-result       同上
x-codex-relay-error        同上
x-codex-relay-request-id   同上
```

与请求侧不同，响应侧不能只按请求代回写。请求没有控制头时无法可靠推断代；而缺少归因头
的 ingress 会 fail closed 成 `502 relay_unavailable`——按请求代回写会让另一代 ingress
把每个响应都判成 relay 故障。双写的成本只是几个头，且两个 ingress 都会在回给客户端前
按前缀剥掉。

写入前先无条件删除两代同名头，避免上游伪造归因（`stamp_control_headers`）。

## 5. ingress 侧：发当前代、读两代、剥两代

- **发送**：`src/relay/client.ts` 用 `CURRENT_VERSION` 同时驱动签名 version 与 envelope
  头名，两者不可能错配（v2 域签名配 v1 头名会被 relay 当成 v1 验签而失败）。
- **读取归因**：`src/relay/attribution.ts` 按 `x-egress-relay-*` → `x-codex-relay-*`
  顺序取值，先当前代后 legacy。缺 result 仍 fail closed。
- **剥离客户端输入**：`src/headers.ts` 的 `isRelayControlHeader()` 匹配两个前缀。
  两个 ingress 都是开放入口，没有客户端凭据，这条前缀规则是唯一阻止调用者伪造
  envelope 或伪造归因的机制。只要还有 relay 读 legacy 名字，legacy 前缀就必须留在
  strip set 里——**永久保留**比按代收窄安全。
- **剥离响应**：回给客户端的响应按前缀去掉两代控制头，双写不会泄露到客户端。

relay 侧 `decode_header_block()` 也拒绝签名 block 内出现任一前缀的头：block 虽然已签名，
但转发一个 live ingress 会读的控制头仍可污染归因。

## 6. 迁移顺序

由 fail-closed 的一侧决定顺序：ingress 缺归因头会 502，所以先上 relay。

1. **relay 先部署**（双代读请求、双代写响应）。此时线上 ingress 仍发 v1，relay 按
   `Legacy` 正常处理。
2. 观察 relay 正常服务 v1。
3. **再部署两个 ingress**（发 v2、读两代、剥两代）。两个 ingress 可任意先后，互不依赖。
4. 观察两代都正常后，才谈是否移除 v1。移除 v1 需要单独一轮，且必须先确认没有任何
   ingress 或运维 probe 仍发 v1。

回滚方向相反：先回滚 ingress 到 v1，relay 仍能接受；relay 回滚到只读 v1 之前，必须
确认没有 ingress 在发 v2。

## 7. 运维 probe

`egress-relay/scripts/relay_probe.py` 默认签 v2，`--v1` 签上一代——这是在真实 relay 上
验证双读窗口的方式，不需要改代码或改 Worker。

```bash
python3 egress-relay/scripts/relay_probe.py --selftest              # 两代都比对 fixture
python3 egress-relay/scripts/relay_probe.py RELAY TARGET [METHOD] [BODY]        # v2
python3 egress-relay/scripts/relay_probe.py --v1 RELAY TARGET [METHOD] [BODY]   # v1
```

`--selftest` 先跑，用来把 probe 自身的 bug 与 relay 故障区分开：probe 对不上 fixture
时，问题在 probe，不在 relay。

## 8. 不在本次变更范围内

- relay 侧环境变量仍是 `CODEX_RELAY_*`，VPS 的 `relay.env` 不动。这样回滚到旧二进制时
  本地配置依然可用。
- Cloudflare 线上 Worker 名 `codex-worker-relay` / `claude-worker-relay` 不动：改名会创建
  新 Worker 并重新绑定路由。
- Claude 的 `identitySalt: "claude-worker-relay/v1"` 不动：它参与 API key → 设备/会话身份
  派生，改动会让上游把同一个 key 当成新设备。
- systemd 部署路径 `/opt/codex-https-relay` 不动。
- v1 fixture 不动。
