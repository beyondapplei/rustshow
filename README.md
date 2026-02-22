# rustshow

`rustshow` 现在只保留一个功能：基于 VetKeys 的 A/B 消息加密与解密（前端 React + Internet Identity）。

- A 使用 II 登录后：填写 B 的 principal 和消息，生成密文（16 进制）。
- B 使用 II 登录后：粘贴密文（16 进制）并解密。

## 前端界面说明

- 主界面只显示功能按钮（便于后续扩展到更多功能）。
- 点击功能按钮后，以全屏界面打开该功能。
- 功能页内 II 登录按钮只有一个：未登录显示 `II 登录`，登录后自动切换为 `II 登出`。

## II 登录（本地 / IC 自动选择）

- 本地环境（`/api`、`localhost`、`127.0.0.1`）自动使用本地 II。
- 当前本地 II 默认 canister id：`uxrrr-q7777-77774-qaaaq-cai`
- 本地 II 登录地址会自动使用：
  `http://uxrrr-q7777-77774-qaaaq-cai.localhost:4943/#authorize`
- 非本地环境自动使用 IC 的 Internet Identity。

## 后端接口（仅保留 2 个）

- `ibe_public_key_hex() -> variant { Ok: text; Err: text }`
- `ibe_decryption_key_for_caller_hex(transport_public_key_hex: text) -> variant { Ok: text; Err: text }`

说明：
- 后端固定使用 `test_key_1`（BLS12-381 G2）。
- IBE context 固定为 `rustshow-ibe-v1`。
- 解密 key 的 `input` 使用当前登录用户 `Principal` 的原始字节（与前端 `IbeIdentity.fromPrincipal(...)` 保持一致）。

## 前端流程

1. 主界面点击 `VetKeys 私密消息` 按钮进入功能页。
2. A 点击 `II 登录`，输入 B principal + 明文，点击“生成密文”。
3. 把密文发给 B。
4. B 点击 `II 登录`，粘贴密文（16 进制），点击“解密”。

## 前端实现说明

- 前端使用 `@dfinity/vetkeys` 做 IBE 加密/解密。
- 前端调用后端接口时使用 `dfx generate` 生成的声明（`/src/declarations/backend`），不再手写后端 Candid 声明。

## 本地开发

```bash
npm install
npm run dev --workspace frontend
```

后端 Rust 校验：

```bash
cargo check -p backend
```
