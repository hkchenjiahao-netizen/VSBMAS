# 文件夹摘要：`auction_house`

## 用途
Riggs **密封竞标拍卖**核心 crate：`ark-*` Groth16/R1CS、依赖本地 `rsa`、`timed_commitments`、`range_proofs`。

## 关键路径
- `src/` — 电路与拍卖逻辑实现。
- `Cargo.toml` — 依赖与 feature。

## AI 检索
修改拍卖电路、标的约束或与 TC/范围证明接口 → **此 crate**。
