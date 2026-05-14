use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::serialize::{BidConstraintProofs, BidProposalView, TcOpeningView};

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct BidRankings {
    #[serde(default)]
    pub highest_user_id: Option<u32>,
    #[serde(default)]
    pub highest_amount: Option<u32>,
    #[serde(default)]
    pub second_user_id: Option<u32>,
    #[serde(default)]
    pub second_amount: Option<u32>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(tag = "type")]
pub enum Event {
    Hello,

    AccountCreated {
        id: u32,
        name: String,
        balance: u32,
    },

    /// Wallet snapshot for classroom HUD (total / available / frozen-in-bids).
    AccountBalanceSnapshot {
        user_id: u32,
        total: u32,
        available: u32,
        frozen: u32,
    },

    Deposit {
        id: u32,
        amount: u32,
        new_balance: u32,
    },

    AuctionCreated {
        id: u32,
        item_name: String,
        item_uri: Option<String>,
        reserve_price: u32,
        total_duration_secs: u64,
        round_duration_secs: u64,
    },

    PhaseTransition {
        auction_id: u32,
        from_phase: String,
        to_phase: String,
        #[serde(default)]
        deadline_epoch_ms: Option<u64>,
    },

    BidSubmitted {
        auction_id: u32,
        user_id: u32,
        prove_ms: u128,
        verify_ms: u128,
        bid_view: BidProposalView,
        /// Part B：`bid >= reserve_price` 与 `bid > prev_round_high_bid` 的附加 ZK 约束证明。
        #[serde(default)]
        constraint_proofs: Option<BidConstraintProofs>,
    },

    SelfOpened {
        auction_id: u32,
        user_id: u32,
        bid_revealed: u32,
        opening: TcOpeningView,
        #[serde(default)]
        rankings: Option<BidRankings>,
    },

    ForceOpened {
        auction_id: u32,
        user_id: u32,
        bid_revealed: Option<u32>,
        opening: TcOpeningView,
        #[serde(default)]
        rankings: Option<BidRankings>,
    },

    /// 诚实强揭：顺序平方进度（与 `TIME_PARAM` 一致）。
    ForceOpenProgress {
        auction_id: u32,
        user_id: u32,
        steps_done: u64,
        steps_total: u64,
        elapsed_ms: u64,
    },

    /// 学生 brute-force 演示：链完成并解密出 bid（与真实强揭一致；demo only）。
    BruteForceCracked {
        task_id: String,
        auction_id: u32,
        user_id: u32,
        bid_revealed: u32,
        squarings_done: u64,
        elapsed_ms: u64,
    },

    Withdraw {
        user_id: u32,
        amount: u32,
    },

    Settled {
        auction_id: u32,
        price: u32,
        winners: Vec<u32>,
    },

    VerificationFailed {
        actor: u32,
        auction_id: Option<u32>,
        reason: String,
        category: String,
    },

    RoundAdvanced {
        auction_id: u32,
        new_round: u32,
        streak: u32,
        current_riggs_auction_id: u32,
        #[serde(default)]
        leader: Option<u32>,
    },

    /// 真实 VSBMAS 一轮已打包进入本地 DemoBlockchain（PoW 教学链）；不包含重入挖矿逻辑。
    RoundBlockMined {
        session_top_id: u32,
        riggs_auction_id: u32,
        round: u32,
        block_index: u64,
        block_hash: String,
        tx_count: usize,
        valid: bool,
    },

    /// Sequential RSW-style squaring progress (demo; exponent is 2^T squarings).
    BruteForceProgress {
        task_id: String,
        auction_id: u32,
        target_user_id: u32,
        squarings_done: u64,
        total_sequential_steps: String,
        time_param_t: u64,
        rate_per_sec: f64,
        estimated_total_secs: f64,
        elapsed_ms: u64,
    },

    BruteForceStopped {
        task_id: String,
        reason: String,
        squarings_done: u64,
    },
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct EventEnvelope {
    pub ts: String,
    pub seq: u64,
    /// v4：本条事件所属的 backend boot 会话 id；`/events?since_boot=true` 时
    /// 前端用此字段过滤掉旧 JSONL 中的陈旧事件（例如 `T=40` 的老 ForceOpened）。
    #[serde(default)]
    pub boot_id: String,
    #[serde(flatten)]
    pub event: Event,
}

impl EventEnvelope {
    pub fn wrap(seq: u64, boot_id: String, event: Event) -> Self {
        Self {
            ts: OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap(),
            seq,
            boot_id,
            event,
        }
    }
}
