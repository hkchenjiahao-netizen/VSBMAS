# 文件夹摘要：`.bootstrap_vsbmas_03`

## 用途
**Cargo workspace 脚手架**：`backend`、`crates/vsbmas_core`、`crates/vsbmas_round`。`Cargo.toml` 中 Riggs 依赖路径写作 `../riggs/...`，对应本仓库需在 WSL/Linux 下把 Riggs 置于 `~/riggs` 或与路径约定一致后再编译。

## 关键文件
| 文件 | 说明 |
|:---|:---|
| `Cargo.toml` | workspace members 与 workspace.dependencies |
| `rust-toolchain.toml` | Rust 工具链约束 |
| `backend/` | Axum HTTP 服务骨架 |
| `crates/vsbmas_core/` | 参数、拍卖类型别名、序列化 hex |
| `crates/vsbmas_round/` | 多轮 RoundManager |
| `data/` | 运行时数据占位（如 `.gitkeep`） |
| `web/` | 前端占位 |

## AI 何时改这里
从零按引导文档「新建工作空间」步骤初始化工程；日常迭代后端多在 **`_wsl_sync`** 与本骨架合并时需对齐路径。
