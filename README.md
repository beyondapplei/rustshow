# rustshow

`rustshow` 是一个用 Rust 实现 canister 后端、React 实现前端的功能演示项目，当前已将 `motokoshow` 的核心功能用 Rust 重写并接入统一首页按钮入口。

当前功能：
- `VetKeys 私密消息`：A 登录后给 B principal 加密；B 登录后解密。
- `Threshold ECDSA (ETH 验签)`：A 登录后做链上 Threshold ECDSA(secp256k1) 签名；B 仅用 `ETH 地址 + 原文 + 签名` 在前端本地验证。
- `II 多链钱包（演示）`：钱包首页 UI + 链切换 + 钱包总览；当前优先接入 EVM 链公钥读取与地址推导。

## 前端界面说明

- 主界面只显示功能按钮（便于继续扩展到更多功能）。
- 点击功能按钮后，以全屏界面打开对应功能页。
- 功能页内 II 登录按钮只有一个：未登录显示 `II 登录`，登录后自动切换为 `II 登出`。

## II 登录（本地 / IC 自动选择）

- 本地环境（`/api`、`localhost`、`127.0.0.1`、`*.localhost`）自动使用本地 II。
- 当前本地 II 默认 canister id：`uxrrr-q7777-77774-qaaaq-cai`
- 本地 II 登录地址（自动）：
  `http://uxrrr-q7777-77774-qaaaq-cai.localhost:4943/#authorize`
- 非本地环境自动使用 IC 的 Internet Identity。

## 功能 1：VetKeys 私密消息（A -> B）

流程：
1. A 使用 II 登录。
2. A 填写 B 的 principal 和消息，生成密文（hex）。
3. A 将密文发给 B。
4. B 使用 II 登录，粘贴密文并解密。

实现要点（Rust 重写，对齐 motokoshow）：
- 前端使用 `@dfinity/vetkeys` 做 IBE 加密/解密。
- 后端支持 `motokoshow` 风格示例接口（`vetkdPublicKeyExample / vetkdDeriveKeyExample / vetkdCallerInputHex`）。
- 默认 VetKD 参数：
  - `keyName = test_key_1`
  - `context = motoko-show`
- 密文使用打包格式（包含 recipient principal bytes、derived public key、ciphertext），解密时会校验：
  - 当前登录账号是否是目标 B
  - 当前链环境（DPK）是否与密文一致（可识别本地链重启导致的不匹配）
  - 前端显示 principal 与后端实际 caller 是否一致

兼容保留接口（旧版简化接口）：
- `ibe_public_key_hex()`
- `ibe_decryption_key_for_caller_hex(transport_public_key_hex)`

## 功能 2：Threshold ECDSA（ETH 地址验签）

流程：
1. A 使用 II 登录。
2. A 输入原文，前端按 `Ethereum personal_sign` 规则计算消息哈希。
3. 后端调用 Threshold ECDSA(secp256k1) 对哈希签名。
4. 前端恢复公钥并生成 `r||s||v` 格式签名（hex）。
5. B 只用 `A ETH 地址 + 原文 + 签名` 在前端本地验签。

实现要点（Rust 重写，对齐 motokoshow）：
- 后端支持 `motokoshow` 风格示例接口（`ecdsaPublicKeyExample / ecdsaSignMessageHashExample`）。
- 前端验签支持 `64` 或 `65` 字节 hex 签名：
  - `64` 字节：`r||s`
  - `65` 字节：`r||s||v`
- ECDSA key name 自动按环境选择：
  - 本地：`dfx_test_key`
  - IC：`test_key_1`

兼容保留接口（当前页也可回退使用）：
- `ecdsa_public_key_for_caller_hex()`
- `ecdsa_sign_hash_hex_for_caller(message_hash_hex)`

## 功能 3：II 多链钱包（演示）

流程（当前版本）：
1. 进入 `II 多链钱包（演示）` 功能页。
2. 使用 II 登录。
3. 调用 `wallet_networks` 获取支持链列表。
4. 选择链并调用 `wallet_overview` 获取钱包总览。
5. 对于 EVM 链（`eth / sepolia / base`），前端根据后端返回的 secp256k1 公钥推导 ETH 地址。

当前已接入：
- 钱包网络列表（多链静态配置）
- 钱包总览结构（caller、链信息、主资产占位、公钥材料）
- EVM 链链钥公钥读取（ETH / Sepolia / Base）
- 前端 ETH 地址推导（由压缩 secp256k1 公钥推导）

当前未接入（占位）：
- 实时余额查询
- 多资产列表
- 发送/转账流程
- 非 EVM 链地址生成与签名/转账

后端实现说明（Rust）：
- 新增 `wallet_app.rs`，提供 `wallet_networks / wallet_overview`。
- `wallet_overview` 当前返回 `WalletOverviewResult`（`Ok WalletOverviewOut | Err text`）。
- EVM 公钥读取优先尝试本地 key `dfx_test_key`，失败后回退 `test_key_1`。

## 当前后端接口（Candid）

`backend/backend.did` 当前包含：
- `vetkdPublicKeyExample(text, text) -> Result`
- `vetkdDeriveKeyExample(blob, text, text) -> Result`
- `vetkdCallerInputHex() -> text`（query）
- `ecdsaPublicKeyExample(text) -> Result`
- `ecdsaSignMessageHashExample(blob, text) -> Result`
- `ibe_public_key_hex() -> Result`
- `ibe_decryption_key_for_caller_hex(text) -> Result`
- `ecdsa_public_key_for_caller_hex() -> Result`
- `ecdsa_sign_hash_hex_for_caller(text) -> Result`
- `wallet_networks() -> vec WalletNetworkInfo`（query）
- `wallet_overview(text, opt text, opt text) -> WalletOverviewResult`

其中 `Result = variant { Ok : text; Err : text }`

钱包类型（简化）：
- `WalletNetworkInfo`：链 id/kind/name/主资产符号/能力标记/默认 RPC
- `WalletOverviewOut`：caller、selectedNetwork、primaryAmount、evmAddress、evmPublicKeyHex、balances
- `WalletOverviewResult = variant { Ok : WalletOverviewOut; Err : text }`

## 声明文件与开发说明

- 前端调用后端接口使用 `dfx generate` 生成的声明（`/src/declarations/backend`）。
- 允许执行：`dfx generate`
- 本仓库协作约定：不由助手执行 `dfx deploy`（由开发者手动执行）。

本地开发：

```bash
npm install
npm run dev --workspace frontend
```

本地生成声明（可执行）：

```bash
dfx generate
```

后端校验：

```bash
cargo check -p backend
```
