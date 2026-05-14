//! 真实 VSBMAS 一轮 -> 本地 DemoBlockchain 单区块打包。
//! 仅从 `MiningSnapshot` + `data/audit.jsonl` 组装交易。

use std::collections::{BTreeMap, HashMap};
use std::path::Path;
use std::sync::Arc;

use serde::Deserialize;
use serde_json::{json, Value};
use crate::blockchain::DemoBlockchain;
use crate::state::{AppState, MiningSnapshot};
use vsbmas_round::MultiRoundStatus;

#[derive(Clone, Debug, serde::Serialize)]
pub struct MineOk {
    pub block_index: u64,
    pub block_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

#[derive(Debug)]
pub enum MineResult {
    SkippedDuplicate { block_index: u64 },
    Mined(MineOk),
    Failed(String),
}

#[derive(Clone, Deserialize, Debug)]
struct AuditLineBid {
    #[serde(default)]
    seq: u64,
    #[serde(default)]
    boot_id: Option<String>,
    #[serde(rename = "type")]
    ty: Option<String>,
    auction_id: Option<u32>,
    user_id: Option<u32>,
    prove_ms: Option<u128>,
    verify_ms: Option<u128>,
    bid_view: Option<BidViewPartial>,
}

#[derive(Clone, Deserialize, Debug)]
struct BidViewPartial {
    ped_commit_hex: Option<String>,
    total_proof_size_bytes: Option<usize>,
}

#[derive(Clone, Deserialize, Debug)]
struct AuditOpen {
    seq: Option<u64>,
    boot_id: Option<String>,
    #[serde(rename = "type")]
    ty: Option<String>,
    auction_id: Option<u32>,
    user_id: Option<u32>,
}

fn ped_preview(hex: Option<&String>) -> String {
    let s = hex.map(|x| x.as_str()).unwrap_or("");
    let t = s.trim_start_matches("0x");
    if t.len() <= 20 {
        t.to_string()
    } else {
        format!("{}…{}", &t[..10], &t[t.len().saturating_sub(10)..])
    }
}

#[derive(Clone, Debug)]
pub(crate) struct AggBid {
    prove_ms: u128,
    verify_ms: u128,
    range_proof_sz: usize,
    ped_preview: String,
}

/// 最近一次 Self vs Force reveal（seq 递增覆盖）。
fn open_method_map(content: &str, boot_sel: Option<&str>, riggs: u32) -> BTreeMap<u32, String> {
    let mut modes: HashMap<u32, (u64, String)> = HashMap::new();
    for line in content.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let v: Result<AuditOpen, _> = serde_json::from_str(line);
        match v {
            Ok(open) => {
                if boot_sel.is_some_and(|b| open.boot_id.as_deref().unwrap_or("") != b) {
                    continue;
                }
                if open.auction_id != Some(riggs) {
                    continue;
                }
                let seq = open.seq.unwrap_or(0);
                let ty = open.ty.unwrap_or_default();
                if !(ty == "SelfOpened" || ty == "ForceOpened") {
                    continue;
                }
                let Some(uid) = open.user_id else { continue };
                let method: String = if ty == "SelfOpened" {
                    "self".into()
                } else {
                    "force".into()
                };
                modes
                    .entry(uid)
                    .and_modify(|e| {
                        if seq >= e.0 {
                            *e = (seq, method.clone());
                        }
                    })
                    .or_insert((seq, method));
            }
            Err(_) => {}
        }
    }
    modes.into_iter().map(|(k, (_, m))| (k, m)).collect()
}

fn agg_bids_latest(content: &str, boot_sel: Option<&str>, riggs: u32) -> HashMap<u32, AggBid> {
    let mut staged: HashMap<u32, (u64, AggBid)> = HashMap::new();
    for line in content.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let v: Result<AuditLineBid, _> = serde_json::from_str(line);
        match v {
            Ok(ev) => {
                if ev.ty.as_deref() != Some("BidSubmitted") {
                    continue;
                }
                if boot_sel.is_some_and(|b| ev.boot_id.as_deref().unwrap_or("") != b) {
                    continue;
                }
                if ev.auction_id != Some(riggs) || ev.user_id.is_none() {
                    continue;
                }
                let uid = ev.user_id.unwrap();
                let seq = ev.seq;
                let ped =
                    ped_preview(ev.bid_view.as_ref().and_then(|bv| bv.ped_commit_hex.as_ref()));
                let rsp = ev.bid_view.as_ref().and_then(|bv| bv.total_proof_size_bytes).unwrap_or(0);
                let entry = AggBid {
                    prove_ms: ev.prove_ms.unwrap_or(0),
                    verify_ms: ev.verify_ms.unwrap_or(0),
                    range_proof_sz: rsp,
                    ped_preview: ped,
                };
                staged.entry(uid).and_modify(|e| {
                    if seq >= e.0 {
                        *e = (seq, entry.clone());
                    }
                }).or_insert((seq, entry));
            }
            Err(_) => {}
        }
    }
    staged.into_iter().map(|(k, (_, v))| (k, v)).collect()
}

pub fn audit_seq_extent_for_boot(
    content: &str,
    boot_sel: Option<&str>,
    riggs: u32,
) -> Option<(u64, u64, usize)> {
    let mut acc: Vec<u64> = Vec::new();
    for line in content.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let Ok(v) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        match v.as_object() {
            None => {}
            Some(m) => {
                if boot_sel.is_some_and(|b| {
                    m.get("boot_id")
                        .and_then(|x| x.as_str())
                        .unwrap_or("") != b
                }) {
                    continue;
                }
                let ty = m.get("type").and_then(|x| x.as_str()).unwrap_or("");
                let aid = m.get("auction_id").and_then(|x| x.as_u64()).unwrap_or(0) == riggs as u64;
                let hits = aid
                    && matches!(
                        ty,
                        "BidSubmitted" | "SelfOpened" | "ForceOpened" | "PhaseTransition"
                            | "Settled" | "VerificationFailed"
                    );
                if hits {
                    if let Some(seq) = m.get("seq").and_then(|x| x.as_u64()) {
                        acc.push(seq);
                    }
                }
            }
        }
    }
    let n = acc.len();
    if n == 0 {
        None
    } else {
        let lo = acc.iter().copied().min().unwrap_or(0);
        let hi = acc.iter().copied().max().unwrap_or(lo);
        Some((lo, hi, n))
    }
}

fn mr_status_zh(s: &MultiRoundStatus) -> &'static str {
    match s {
        MultiRoundStatus::Active => "进行中",
        MultiRoundStatus::Complete => "已结束",
    }
}

pub fn explanation_zh(snapshot: &MiningSnapshot) -> String {
    let n = snapshot.bids_n as usize;
    let r = snapshot.round_number;
    format!(
        "第 {} 轮开标完成：{} 名投标者的承诺摘要、ZK 证明规模、揭示路径与本轮结算快照已写入本地 PoW 教学链区块，便于课堂演示哈希链一致性与篡改检测。",
        r, n
    )
}

#[derive(Clone, Debug)]
pub struct AuditRoundCtx {
    pub bids: HashMap<u32, AggBid>,
    pub open_method: BTreeMap<u32, String>,
    pub seq_range_json: Value,
    pub audit_event_count: usize,
}

impl AuditRoundCtx {
    pub fn scan(content: &str, boot_sel: Option<&str>, riggs: u32) -> Self {
        let bids = agg_bids_latest(content, boot_sel, riggs);
        let open_method = open_method_map(content, boot_sel, riggs);
        let ext = audit_seq_extent_for_boot(content, boot_sel, riggs).unwrap_or((0, 0, 0));
        Self {
            bids,
            open_method,
            seq_range_json: json!({"min": ext.0, "max": ext.1}),
            audit_event_count: ext.2,
        }
    }
}

pub fn vsbmas_round_transaction(snapshot: &MiningSnapshot, ctx: &AuditRoundCtx) -> Value {
    let mut participants: Vec<Value> = Vec::new();

    let mut uids: Vec<u32> = snapshot.revealed_by_uid.iter().map(|(u, _)| *u).collect();
    uids.sort_unstable();

    for uid in uids.into_iter() {
        let bid_revealed = snapshot
            .revealed_by_uid
            .iter()
            .find(|(x, _)| *x == uid)
            .map(|(_, a)| *a)
            .unwrap_or(0);
        let om = ctx
            .open_method
            .get(&uid)
            .cloned()
            .unwrap_or_else(|| "unknown".into());
        let bs = ctx.bids.get(&uid);
        participants.push(json!({
            "user_id": uid,
            "bid_commitment_preview": bs.map(|b| b.ped_preview.clone()).unwrap_or_else(|| "?".into()),
            "range_proof_size": bs.map(|b| b.range_proof_sz).unwrap_or(0usize),
            "prove_ms": bs.map(|b| b.prove_ms).unwrap_or(0u128),
            "verify_ms": bs.map(|b| b.verify_ms).unwrap_or(0u128),
            "open_method": om,
            "bid_revealed": bid_revealed,
        }));
    }

    json!({
        "type": "VsbmasRoundCommitted",
        "session_top_id": snapshot.session_top_id,
        "riggs_auction_id": snapshot.riggs_auction_id,
        "round": snapshot.round_number,
        "item_name": snapshot.item_name,
        "reserve_price": snapshot.reserve_price,
        "bid_count": snapshot.bids_n,
        "revealed_count": snapshot.revealed_n,
        "participants": participants,
        "winner_user_id": snapshot.winner,
        "settlement_price": snapshot.settlement_price,
        "highest_amount": snapshot.rankings.highest_amount,
        "second_amount": snapshot.rankings.second_amount,
        "streak": snapshot.streak_snap,
        "round_status": mr_status_zh(&snapshot.round_status_snapshot),
        "event_seq_range": ctx.seq_range_json.clone(),
        "audit_event_count": ctx.audit_event_count,
        "created_at_epoch_ms": now_epoch_ms(),
        "empty_round": snapshot.empty_round,
        "explanation_zh": explanation_zh(snapshot),
    })
}

fn now_epoch_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

pub async fn mine_from_snapshot(app: Arc<AppState>, snapshot: MiningSnapshot) -> MineResult {
    let key = (snapshot.session_top_id, snapshot.riggs_auction_id);
    {
        let mm = app.mined_round_blocks.lock().await;
        if let Some(&idx) = mm.get(&key) {
            return MineResult::SkippedDuplicate {
                block_index: idx,
            };
        }
    }

    let path_str = app.audit.path.as_path().to_string_lossy();
    let content = tokio::fs::read_to_string(Path::new(path_str.as_ref()))
        .await
        .unwrap_or_default();

    let ctx = AuditRoundCtx::scan(&content, Some(app.boot_id.as_str()), snapshot.riggs_auction_id);
    let tx = vsbmas_round_transaction(&snapshot, &ctx);

    let mut bc = app.blockchain.lock().await;
    bc.add_pending(tx);
    match bc.mine_pending_block() {
        Ok(()) => {
            let idx = bc.chain.last().map(|b| b.index).unwrap_or(0);
            let hash = bc.chain.last().map(|b| b.hash.clone()).unwrap_or_default();
            drop(bc);

            let mut mmap = app.mined_round_blocks.lock().await;
            mmap.insert(key, idx);
            let mut retr = app.mining_retry_snapshots.lock().await;
            retr.remove(&snapshot.riggs_auction_id);
            MineResult::Mined(MineOk {
                block_index: idx,
                block_hash: hash.clone(),
                message: Some("真实轮次已成功打包挖矿".into()),
            })
        }
        Err(e) => MineResult::Failed(e.to_string()),
    }
}

pub fn chain_real_summaries(bc: &DemoBlockchain) -> (usize, Option<Value>) {
    let mut n = 0usize;
    let mut latest: Option<Value> = None;
    for b in bc.chain.iter() {
        for t in &b.transactions {
            if t.get("type").and_then(|x| x.as_str()) == Some("VsbmasRoundCommitted") {
                n += 1;
                latest = Some(json!({
                    "block_index": b.index,
                    "hash": b.hash,
                    "riggs_auction_id": t.get("riggs_auction_id"),
                    "session_top_id": t.get("session_top_id"),
                    "round": t.get("round"),
                    "winner_user_id": t.get("winner_user_id"),
                    "settlement_price": t.get("settlement_price"),
                    "transaction_count": b.transactions.len(),
                }));
            }
        }
    }
    (n, latest)
}
