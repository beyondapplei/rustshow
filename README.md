# rustshow

`rustshow` 是一个基于 ICP 的 Rust 示例项目，包含一个后端 canister 和一个前端静态页面，用于演示前后端调用与稳定存储（stable memory）能力。

## 功能说明

1. 问候语前缀持久化
后端 `backend` canister 使用 `ic-stable-structures` 将问候语前缀存储在 stable memory 中，升级后数据仍可保留。

2. 动态问候生成
后端提供 `greet(name)` 查询接口，按“前缀 + 姓名 + !”格式返回问候语。

3. 可更新问候语前缀
后端提供 `set_greeting(prefix)` 更新接口，可动态修改问候语前缀内容。

4. 前端交互调用
前端页面提供姓名输入表单，提交后调用后端 `greet` 并展示返回结果。

## 项目结构

```text
.
├── backend/          # Rust canister 代码
├── frontend/         # 前端页面与 Vite 配置
├── dfx.json          # canister 配置
└── README.md
```

## 本地运行

### 1. 安装依赖

- `dfx`（IC SDK）
- Rust 工具链
- `candid-extractor`
- Node.js / npm

### 2. 启动本地副本网络

```bash
dfx start --background
```

### 3. 安装前端依赖并部署

```bash
npm install
dfx deploy
```

部署完成后，终端会输出本地访问地址。

## 接口说明

- `set_greeting(prefix: text) -> ()`：更新问候语前缀（update）
- `greet(name: text) -> text`：返回问候语（query）
