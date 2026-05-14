# 文件夹摘要：`vsbmas_core`

## 用途
**共享核心库**：`params`（模数位宽等）、`house`（与 Riggs 拍卖对接）、`serialize`（CanonicalSerialize → hex）、`events`（若扩展）。

## 关键文件
- `src/lib.rs` — 模块导出。
- `src/params.rs`、`house.rs`、`serialize.rs` — 引导文档第 05–06 步核心产出。

## AI 检索
前后端字段对齐、hex 格式、拍卖 API 封装 → **优先改此 crate**。
