# 文件夹摘要：`riggs-master`

## 用途
**Riggs 上游 Cargo workspace**（根 `Cargo.toml` members：`rsa`、`timed_commitments`、`range_proofs`、`solidity_test_utils`、`solidity`、`pari_factor`、`auction_house`）。密封竞标拍卖密码学与 Solidity 绑定依赖于此。

## AI 检索
| 需求 | 目录 |
|:---|:---|
| 拍卖 SNARK/R1CS | `auction_house/` |
| RSA/PoE/HOG | `rsa/` |
| 定时承诺 TC | `timed_commitments/` |
| Bulletproof 范围证明 | `range_proofs/` |
| Solidity 合约与封装 | `solidity/` |
| EVM 测试辅助 | `solidity_test_utils/` |
| PARI 因子分解绑定 | `pari_factor/`（含上游 `depend/`） |

基线编译：`cargo build --release --workspace`（见引导文档 `02`）。
