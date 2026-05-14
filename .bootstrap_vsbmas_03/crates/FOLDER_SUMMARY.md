# 文件夹摘要：`crates`

## 用途
workspace 内的 **库 crate** 容器：`vsbmas_core`、`vsbmas_round`。

## 子目录
| 目录 | 角色 |
|:---|:---|
| `vsbmas_core/` | 密码学参数、拍卖封装、前端视图序列化 |
| `vsbmas_round/` | 多轮拍卖状态机 |

## AI 检索
业务逻辑优先在对应 crate 的 `src/*.rs`，而非 backend 重复实现。
