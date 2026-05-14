use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicU64};
use std::sync::Arc;
use std::time::Instant;

use tokio::sync::{broadcast, Mutex};
use vsbmas_core::events::BidRankings;
use vsbmas_core::house::World;
use vsbmas_core::serialize::TcOpeningView;
use vsbmas_round::RoundManager;

use crate::audit::Audit;
use crate::blockchain::DemoBlockchain;

pub struct BruteForceHandle {
    pub cancel: Arc<AtomicBool>,
    pub progress: Arc<AtomicU64>,
    pub auction_id: u32,
    pub target_user_id: u32,
    pub started: Instant,
}

/// v4.1：幂等 force-open 的缓存结果。重复请求命中已揭示用户时，直接回放此结构，
/// 不再重跑 ~131s 的 RSW 节流循环。
#[derive(Clone, Debug)]
pub struct ForceOpenCached {
    pub bid_revealed: u32,
    pub opening: TcOpeningView,
    pub rankings: BidRankings,
    pub computation_ms: u64,
    /// `"teacher"`（老师按钮或自动批处理）/ `"bruteforce"`（学生暴力破解结算）。
    pub trigger: String,
}

#[derive(Clone)]
pub struct AppState {
    pub world: Arc<Mutex<World>>,
    pub rounds: Arc<Mutex<HashMap<u32, RoundManager>>>,
    pub events_tx: broadcast::Sender<String>,
    pub audit: Arc<Audit>,
    pub bruteforce_tasks: Arc<Mutex<HashMap<String, BruteForceHandle>>>,
    /// v4：启动时生成的 boot id，用于前端过滤历史审计事件（避免 `/events?since=0`
    /// 把旧版本（T=40 等）的卡片重新贴到 UI 上）。
    pub boot_id: String,
    /// v4.1：当前正在跑 `apply_force_open_honest_emit_progress` 的 `(auction_id, user_id)`
    /// 集合。用于重复点击 force-open / set_phase 时短路 409。
    pub force_open_inflight: Arc<Mutex<HashSet<(u32, u32)>>>,
    /// v4.1：已揭示用户的 force-open 结果缓存，按 `(auction_id, user_id)` 键。
    pub force_open_cache: Arc<Mutex<HashMap<(u32, u32), ForceOpenCached>>>,
    /// 课堂用简易区块链演示（与 Python CLI 同源规则）。
    pub blockchain: Arc<Mutex<DemoBlockchain>>,
}

impl AppState {
    pub async fn new() -> anyhow::Result<Self> {
        let (tx, _rx) = broadcast::channel::<String>(1024);

        if std::env::var("VSBMAS_FRESH_AUDIT").ok().as_deref() == Some("1") {
            let path = std::path::Path::new("data/audit.jsonl");
            if path.exists() {
                let ts = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                let backup = format!("data/audit.jsonl.bak.{ts}");
                let _ = tokio::fs::rename(path, &backup).await;
                tracing::info!(backup = %backup, "VSBMAS_FRESH_AUDIT=1: rotated audit log");
            }
        }

        let audit = Audit::open("data/audit.jsonl").await?;
        let boot_id = uuid::Uuid::new_v4().to_string();
        tracing::info!(boot_id = %boot_id, "VSBMAS backend boot_id");
        let mut demo_chain = DemoBlockchain::empty(3);
        demo_chain.mine_genesis();
        Ok(Self {
            world: Arc::new(Mutex::new(World::bootstrap())),
            rounds: Arc::new(Mutex::new(HashMap::new())),
            events_tx: tx,
            audit: Arc::new(audit),
            bruteforce_tasks: Arc::new(Mutex::new(HashMap::new())),
            boot_id,
            force_open_inflight: Arc::new(Mutex::new(HashSet::new())),
            force_open_cache: Arc::new(Mutex::new(HashMap::new())),
            blockchain: Arc::new(Mutex::new(demo_chain)),
        })
    }
}
