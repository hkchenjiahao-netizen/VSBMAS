# 文件夹摘要：`depend`

## 用途
**第三方依赖源码**：主要为 **`pari`** — PAR/GP 上游完整分发树（`depend/pari/`），体量极大。

## AI 检索约定（重要）
- **不在 `depend/pari/**` 各子目录单独维护 `FOLDER_SUMMARY.md`**：此为上游副本，升级或重装应由 Riggs/README 指引。
- 修改因子分解集成逻辑 → **`pari_factor/src`** 与本 crate 根目录构建脚本。
- 若仅需导航 PAR 文档结构：`depend/pari/doc`、`depend/pari/src` 等为上游原生布局。
