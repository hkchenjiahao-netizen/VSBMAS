# 文件夹摘要：`_wsl_sync`

## 用途
**Windows/WSL 同步用完整工程副本**：单体 Axum 应用（根目录 `main.rs`）、模块 `audit`、`attack`、`blockchain`、`l1`、`mining`、`state`、`vsbmas_core`/`vsbmas_round` 的镜像 Cargo 片段（`*_Cargo.toml`、`lib.rs` 等）、静态前端 `web/`、脚本 `scripts/`、`blockchain_demo/` Python 演示。

## 关键入口（便于 AI grep）
| 路径 | 说明 |
|:---|:---|
| `main.rs` | HTTP/WebSocket 路由与全局状态 |
| `state.rs` | `AppState`、挖矿与缓存等 |
| `blockchain.rs` | 简易链演示逻辑 |
| `audit.rs` / `attack.rs` | 审计与恶意演示 |
| `web/` | `teacher.html`、`student.html`、`display.html`、`blockchain.html`、`assets/` |
| `run_demo.sh` / `run_verify.sh` | Linux 侧脚本 |

## AI 检索指引
改课堂演示后端 API、大屏或区块链扩展 → **优先在本目录修改**，并与 `引导文档/17_*.md` 等对照。
