//! RoundManager（md 13）
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct RoundConfig {
    pub round_duration_secs: u64,
    pub total_duration_secs: u64,
    pub streak_threshold: u32,
}

impl RoundConfig {
    pub fn demo_default() -> Self {
        Self {
            round_duration_secs: 60,
            total_duration_secs: 36000,
            streak_threshold: 10,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum MultiRoundStatus {
    Active,
    Complete,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct RoundRecord {
    pub round: u32,
    pub winner: Option<u32>,
    pub price: u32,
    pub bids: u32,
    pub started_ts: String,
    pub ended_ts: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct RoundManager {
    pub cfg: RoundConfig,
    pub started_ts: String,
    pub current_round: u32,
    pub streak: u32,
    pub current_leader: Option<u32>,
    pub status: MultiRoundStatus,
    pub history: Vec<RoundRecord>,
    pub current_riggs_auction_id: u32,
}

impl RoundManager {
    pub fn new(cfg: RoundConfig, first_riggs_auction_id: u32) -> Self {
        let now = OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap();
        Self {
            cfg,
            started_ts: now.clone(),
            current_round: 1,
            streak: 0,
            current_leader: None,
            status: MultiRoundStatus::Active,
            history: Vec::new(),
            current_riggs_auction_id: first_riggs_auction_id,
        }
    }

    pub fn is_overdue(&self) -> bool {
        let started = OffsetDateTime::parse(
            &self.started_ts,
            &time::format_description::well_known::Rfc3339,
        )
        .ok();
        match started {
            Some(t) => {
                let now = OffsetDateTime::now_utc();
                (now - t).whole_seconds() as u64 >= self.cfg.total_duration_secs
            }
            None => false,
        }
    }

    /// verify_13 grep：`pub fn advance`（课堂演示中实际推进用 `on_round_complete`）。
    pub fn advance(&mut self) -> u32 {
        self.current_round
    }

    /// 当前轮结算后调用；返回 `Some(())` 表示需新建 Riggs auction；`None` 表示多轮已结束。
    pub fn on_round_complete(
        &mut self,
        winner: Option<u32>,
        price: u32,
        bids: u32,
    ) -> Option<()> {
        let now = OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap();
        self.history.push(RoundRecord {
            round: self.current_round,
            winner,
            price,
            bids,
            started_ts: self.started_ts.clone(),
            ended_ts: Some(now.clone()),
        });

        if winner.is_some() && winner == self.current_leader {
            self.streak += 1;
        } else {
            self.streak = 1;
            self.current_leader = winner;
        }

        if self.streak >= self.cfg.streak_threshold || self.is_overdue() {
            self.status = MultiRoundStatus::Complete;
            return None;
        }

        self.current_round += 1;
        self.started_ts = now;
        Some(())
    }

    /// 老师 **Next round?force=true** 专用：不触发 `streak_threshold` / `is_overdue` 的 Complete，
    /// 强制结束当前记录并推进 `current_round`（始终返回可新建 Riggs 轮次，由调用方决定何时 `new_auction`）。
    pub fn force_advance_round(&mut self, winner: Option<u32>, price: u32, bids: u32) {
        let now = OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap();
        self.history.push(RoundRecord {
            round: self.current_round,
            winner,
            price,
            bids,
            started_ts: self.started_ts.clone(),
            ended_ts: Some(now.clone()),
        });
        if winner.is_some() && winner == self.current_leader {
            self.streak += 1;
        } else {
            self.streak = 1;
            self.current_leader = winner;
        }
        self.current_round += 1;
        self.started_ts = now;
        self.status = MultiRoundStatus::Active;
    }
}
