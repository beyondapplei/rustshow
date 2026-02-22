# rustshow

`rustshow` 是一个用 Rust 实现 canister 后端、React 实现前端的功能演示项目，当前已将 `motokoshow` 的核心功能用 Rust 重写并接入统一首页按钮入口。

当前功能：
- `VetKeys 私密消息`：A 登录后给 B principal 加密；B 登录后解密。
- `Threshold ECDSA (ETH 验签)`：A 登录后做链上 Threshold ECDSA(secp256k1) 签名；B 仅用 `ETH 地址 + 原文 + 签名` 在前端本地验证。

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

其中 `Result = variant { Ok : text; Err : text }`

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
