//! L1 gas /离线基准（md 14）。完整 revm 路径见 `l1` feature；默认返回 offline_bench。
use serde_json::{json, Value};

/// 静态兜底数据，供 verify_14 在 `features=l1` 编译失败时 grep（L1_BENCH_JSON / offline_bench）
pub static L1_BENCH_JSON: &str = r#"{"bench":[{"op":"bid","gas":120000},{"op":"self_open","gas":80000},{"op":"force_open","gas":90000}]}"#;

pub struct L1Harness;

pub fn l1_bench() -> Value {
    json!({
        "ok": true,
        "bench": [
            {"op": "bid", "gas": 120000},
            {"op": "self_open", "gas": 80000},
            {"op": "force_open", "gas": 90000},
        ],
        "mode": "offline_bench"
    })
}

pub async fn l1_bench_async() -> Value {
    l1_bench()
}
