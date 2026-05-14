use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use axum::{
    extract::{Path, Query, State, ws::{Message, WebSocket, WebSocketUpgrade}},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::Deserialize;
use serde_json::json;
use tower_http::{cors::CorsLayer, services::{ServeDir, ServeFile}, trace::TraceLayer};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use vsbmas_core::events::{BidRankings, Event};
use vsbmas_core::house::{
    prove_bid_at_least, verify_bid_at_least, DemoAccount, DemoTCOpening, World,
};
use vsbmas_core::params::{calibrate_time_param, time_param, MOD_BITS};
use vsbmas_core::serialize::{
    bid_proposal_view, params_summary, range_proof_hex, tc_opening_view_with_meta,
    BidConstraintProofs, TcOpeningMeta, TcOpeningView,
};
use vsbmas_round::{MultiRoundStatus, RoundConfig, RoundManager};

pub(crate) mod audit;
pub(crate) mod attack;
pub(crate) mod blockchain;
pub(crate) mod l1;
pub(crate) mod mining;
pub(crate) mod state;
use state::{AppState, BruteForceHandle, ForceOpenCached, MiningSnapshot};

pub(crate) async fn emit(s: &AppState, e: Event) {
    match s.audit.emit(e, &s.boot_id).await {
        Ok(env) => {
            let _ = s.events_tx.send(serde_json::to_string(&env).unwrap());
        }
        Err(err) => tracing::error!(?err, "audit emit failed"),
    }
}

fn now_epoch_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

// Specialized helper to avoid generic mess in handlers.
//
// Part B2：`tc_force_meta` 用于**诚实** force-open 路径（顺序平方 + PoE，无陷门），
// 强制标注 `honest_rsw=true`、`demo_simulated_timing=false`，以对答辩负责。
// 若将来切到 B2 降级路径（`apply_force_open_cheating` + timing 模拟），应改调
// `tc_force_meta_simulated` 并同步前端"demo throttling"徽标。
fn tc_force_meta(ms: Option<u64>, poe_ok: Option<bool>) -> TcOpeningMeta {
    TcOpeningMeta {
        computation_ms: ms,
        time_param_t: Some(time_param()),
        modulus_bits: Some(MOD_BITS),
        poe_verify_ok: poe_ok,
        honest_rsw: Some(true),
        demo_simulated_timing: Some(false),
    }
}

/// Part B2：降级/测试路径（陷门快揭 + timing 模拟）的 meta。当前 v3 主路径不走。
#[allow(dead_code)]
fn tc_force_meta_simulated(ms: Option<u64>, poe_ok: Option<bool>) -> TcOpeningMeta {
    TcOpeningMeta {
        computation_ms: ms,
        time_param_t: Some(time_param()),
        modulus_bits: Some(MOD_BITS),
        poe_verify_ok: poe_ok,
        honest_rsw: Some(false),
        demo_simulated_timing: Some(true),
    }
}

/// SELF opening 的 meta：RSW 相关字段不适用，显式置空（修复 v2 里把 poe_verify_ok
/// 误填成 Some(true) 的语义噪声，SELF 分支根本不涉及 PoE）。
fn tc_self_meta() -> TcOpeningMeta {
    TcOpeningMeta::default()
}

/// v4.2 诚实强揭 + `ForceOpenProgress` 事件 + **真** 2^T 顺序平方 + 真 PoE。
///
/// 流程：短锁 prepare 取 (time_pp, ped_pp, comm, bid_stored, bid_id) → spawn_blocking 跑
/// `rsw_force_open_real`（~120s，**不**持有 world.lock；允许其它 auction 并发）→ 短锁 settle
/// 把账户/排名写进 world。返回第三个字段是真 wall-clock 毫秒数。
async fn apply_force_open_honest_emit_progress(
    s: &AppState,
    riggs: u32,
    uid: u32,
) -> Result<(u32, DemoTCOpening, u64), String> {
    // 1) 短锁：prepare。
    let (time_pp, ped_pp, comm, bid_stored, bid_id) = {
        let w = s.world.lock().await;
        w.force_open_prepare(riggs, uid)?
    };

    // 2) 进度转发 task。
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<(u64, u64, u64)>();
    let forward = tokio::spawn({
        let s = s.clone();
        async move {
            while let Some((done, total, elapsed)) = rx.recv().await {
                emit(
                    &s,
                    Event::ForceOpenProgress {
                        auction_id: riggs,
                        user_id: uid,
                        steps_done: done,
                        steps_total: total,
                        elapsed_ms: elapsed,
                    },
                )
                .await;
            }
        }
    });

    // 3) 长计算：spawn_blocking 执行真 2^T 次顺序平方 + 真 Wesolowski PoE::prove + 真 AES 解密。
    let tx2 = tx.clone();
    let t0 = Instant::now();
    let spawn_res = tokio::task::spawn_blocking(move || {
        vsbmas_core::house::rsw_force_open_real(&comm, &time_pp, &ped_pp, &mut |d, t, e| {
            let _ = tx2.send((d, t, e));
        })
    })
    .await;
    drop(tx); // 关闭发送端，forward 循环自然退出。
    let _ = forward.await;
    let ms = t0.elapsed().as_millis() as u64;

    let (bid_revealed, lazy_opening) = match spawn_res {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => return Err(e),
        Err(je) => return Err(format!("blocking task panic/cancel: {je}")),
    };

    // 4) 短锁：settle（幂等）。
    {
        let mut w = s.world.lock().await;
        w.force_open_settle(
            riggs,
            uid,
            bid_id,
            bid_stored,
            bid_revealed,
            lazy_opening.clone(),
        )?;
    }

    Ok((bid_revealed, lazy_opening, ms))
}

/// v4.1 幂等守卫：重复点击 force-open 或 `set_phase(BidSelfOpening)` 再次触达同一个
/// `(auction_id, user_id)` 时，短路到已缓存结果或告知「在途中」，避免串行重跑 RSW。
pub(crate) enum ClaimOutcome {
    /// 本次为首次调用；调用方负责跑完整条 force-open 流程、写 cache 并最终调用
    /// `release_force_open_claim` 释放 in-flight 占位（出错也要释放）。
    Fresh,
    /// 已经揭示过。若带 `Some(cached)` 则含有完整 view；`None` 表示 world 里已有
    /// `revealed_bid_ids` 但本进程 cache 缺失（例如审计回放后的防御分支）。
    AlreadyRevealed(Option<ForceOpenCached>),
    /// 当前有另一个请求正在跑 RSW；调用方应立即返回 409（或 emit 忽略）。
    InFlight,
}

pub(crate) async fn try_claim_force_open(s: &AppState, riggs: u32, uid: u32) -> ClaimOutcome {
    {
        let cache = s.force_open_cache.lock().await;
        if let Some(c) = cache.get(&(riggs, uid)) {
            return ClaimOutcome::AlreadyRevealed(Some(c.clone()));
        }
    }
    {
        let w = s.world.lock().await;
        if let Some(&bid_id) = w.bid_index.get(&(riggs, uid)) {
            if w
                .revealed_bid_ids
                .get(&riggs)
                .map(|s| s.contains(&bid_id))
                .unwrap_or(false)
            {
                return ClaimOutcome::AlreadyRevealed(None);
            }
        }
    }
    {
        let mut inflight = s.force_open_inflight.lock().await;
        if inflight.contains(&(riggs, uid)) {
            return ClaimOutcome::InFlight;
        }
        inflight.insert((riggs, uid));
    }
    ClaimOutcome::Fresh
}

pub(crate) async fn release_force_open_claim(s: &AppState, riggs: u32, uid: u32) {
    s.force_open_inflight.lock().await.remove(&(riggs, uid));
}

pub(crate) async fn store_force_open_cache(
    s: &AppState,
    riggs: u32,
    uid: u32,
    cached: ForceOpenCached,
) {
    s.force_open_cache
        .lock()
        .await
        .insert((riggs, uid), cached);
}

/// 在 `World` 上执行一次自揭（不含 HTTP / emit）；供 `self_open` 与 `set_phase` 批量调用。
fn world_run_self_open(
    w: &mut World,
    auction_id: u32,
    user_id: u32,
    bid: u32,
) -> Result<(TcOpeningView, BidRankings), String> {
    let house_pp = w.house_pp.clone();
    let auction_pp = w.auction_pp.clone();
    let opening = {
        let private = w
            .privates
            .get(&user_id)
            .ok_or_else(|| "unknown user".to_string())?;
        let (stored_bid, opening, _) = private
            .active_bids
            .get(&auction_id)
            .ok_or_else(|| "no active bid".to_string())?;
        if *stored_bid != bid {
            return Err("bid amount mismatch".into());
        }
        opening.clone()
    };
    w.house
        .account_self_open(&house_pp, &auction_pp, auction_id, user_id, bid, &opening)
        .map_err(|e| format!("account_self_open: {e}"))?;
    w.privates
        .get_mut(&user_id)
        .unwrap()
        .confirm_bid_self_open(&house_pp, &auction_pp)
        .map_err(|e| format!("confirm_bid_self_open: {e}"))?;
    *w.self_open_count.entry(auction_id).or_insert(0) += 1;
    if let Some(bid_id) = w.bid_index.get(&(auction_id, user_id)).copied() {
        w.revealed_bid_ids
            .entry(auction_id)
            .or_default()
            .insert(bid_id);
    }
    w.record_reveal(auction_id, user_id, bid);
    // SELF opening：非 RSW 路径，不填 honest_rsw/simulated/poe_verify_ok。
    let ov = tc_opening_view_with_meta(&opening, tc_self_meta());
    let rk = w.bid_rankings_snapshot(auction_id);
    Ok((ov, rk))
}

async fn resolve_riggs_for_path(s: &AppState, path_id: u32) -> u32 {
    let rounds = s.rounds.lock().await;
    if let Some(rm) = rounds.get(&path_id) {
        rm.current_riggs_auction_id
    } else {
        path_id
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "info,backend=debug,tower_http=info".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    // v4.2：启动时对 RSW 单步顺序平方做 micro-bench，按目标秒数（默认 120）反推 T。
    // 必须在 AppState::new()（内部会 gen_time_params_cheating(T)）之前完成。
    let (t_eff, sq_us) = calibrate_time_param();
    tracing::info!(
        "RSW auto-calibrate: sq_us={} t={} → expected 2^T sequential squarings ≈ {} s",
        sq_us,
        t_eff,
        if sq_us == 0 {
            "manual-override".to_string()
        } else {
            format!("{:.1}", (sq_us as f64) * (1u64 << t_eff) as f64 / 1_000_000.0)
        }
    );

    let state = AppState::new().await?;

    {
        let existing = tokio::fs::read_to_string(&state.audit.path)
            .await
            .unwrap_or_default();
        if !existing.contains("\"VerificationFailed\"") {
            emit(
                &state,
                Event::VerificationFailed {
                    actor: 0,
                    auction_id: None,
                    reason: "backend initialization self-check".into(),
                    category: "startup-self-check".into(),
                },
            )
            .await;
        }
    }

    let api = Router::new()
        .route("/health", get(health))
        .route("/params", get(params))
        .route("/events", get(list_events))
        .route("/accounts", post(create_account).get(list_accounts))
        .route("/accounts/:id", get(get_account))
        .route("/accounts/:id/ledger", get(account_ledger))
        .route("/accounts/:id/deposit", post(deposit))
        .route("/auctions", post(create_auction).get(list_auctions))
        .route("/auctions/:id", get(get_auction))
        .route("/auctions/:id/rankings", get(get_rankings))
        .route("/auctions/:id/can_advance", get(can_advance))
        .route("/auctions/:id/pending_users", get(pending_users))
        .route("/auctions/:id/set_phase", post(set_phase))
        .route("/auctions/:id/bid", post(bid))
        .route("/auctions/:id/withdraw", post(withdraw))
        .route("/auctions/:id/self_open", post(self_open))
        .route("/auctions/:id/self_open_intent", post(self_open_intent))
        .route("/auctions/:id/release_loser", post(release_loser))
        .route("/auctions/:id/force_open", post(force_open))
        .route("/auctions/:id/advance_round", post(advance_round))
        .route("/auctions/:id/settle", post(settle))
        .route("/bruteforce/start", post(bruteforce_start))
        .route("/bruteforce/stop", post(bruteforce_stop))
        .route("/bruteforce/status/:task_id", get(bruteforce_status))
        .route("/l1/bench", get(l1_bench_handler))
        .route("/attack/a1_oversize", post(attack::a1_oversize))
        .route("/attack/a2_refuse_self_open", post(attack::a2_refuse_self_open))
        .route("/attack/a3_tampered_proof", post(attack::a3_tampered_proof))
        .route("/attack/a4_replay", post(attack::a4_replay))
        .route("/attack/a5_fake_self_open", post(attack::a5_fake_self_open))
        .route("/attack/a6_peek_ciphertext", post(attack::a6_peek_ciphertext))
        .route("/blockchain/chain", get(blockchain_chain))
        .route("/blockchain/validate", get(blockchain_validate))
        .route("/blockchain/reset", post(blockchain_reset))
        .route("/blockchain/demo-sequence", post(blockchain_demo_sequence))
        .route("/blockchain/tamper", post(blockchain_tamper))
        .route("/blockchain/mine-round/:auction_id", post(blockchain_mine_round))
        .route("/blockchain/round-status/:auction_id", get(blockchain_round_status))
        .with_state(state.clone());

    let app = Router::new()
        .nest("/api", api)
        .route("/ws", get(ws_handler))
        .nest_service("/audit.jsonl", ServeFile::new("data/audit.jsonl"))
        .fallback_service(ServeDir::new("web"))
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], 8080));
    tracing::info!("listening on http://{addr}");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

#[derive(Deserialize)]
struct EventQuery {
    pub since: Option<u64>,
    /// v4：当 `since_boot=true` 时，只返回与当前 backend `boot_id` 匹配的事件。
    /// 用于前端启动时拉取「本次会话」历史，避免历史 JSONL 污染展示。
    #[serde(default)]
    pub since_boot: Option<bool>,
}

async fn list_events(State(s): State<AppState>, Query(q): Query<EventQuery>) -> impl IntoResponse {
    let since = q.since.unwrap_or(0);
    let since_boot = q.since_boot.unwrap_or(false);
    let content = tokio::fs::read_to_string(&s.audit.path).await.unwrap_or_default();
    let mut out = Vec::<serde_json::Value>::new();
    for line in content.lines() {
        if line.is_empty() {
            continue;
        }
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(line) {
            if v.get("seq").and_then(|x| x.as_u64()).unwrap_or(0) < since {
                continue;
            }
            if since_boot {
                let this_boot = v.get("boot_id").and_then(|x| x.as_str()).unwrap_or("");
                if this_boot != s.boot_id {
                    continue;
                }
            }
            out.push(v);
        }
    }
    Json(json!({
        "count": out.len(),
        "boot_id": s.boot_id,
        "events": out
    }))
}

/// 从本轮 World 快照构造 `MiningSnapshot`（在 advance_round 已结算后即可调用）。
fn build_mining_snapshot(
    w: &World,
    session_top_id: u32,
    riggs_auction_id: u32,
    winner: Option<u32>,
    settlement_price: u32,
    bids_n: u32,
    empty_round: bool,
    round_number: u32,
    streak_snap: u32,
    rm_status: MultiRoundStatus,
    rk: BidRankings,
) -> MiningSnapshot {
    let revealed_n = w
        .revealed_bid_ids
        .get(&riggs_auction_id)
        .map(|s| s.len() as u32)
        .unwrap_or(0);
    let mut revealed_by_uid: Vec<(u32, u32)> = w
        .revealed_rankings
        .get(&riggs_auction_id)
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .collect();
    revealed_by_uid.sort_by_key(|x| x.0);
    let item_name = w
        .auction_item_names
        .get(&riggs_auction_id)
        .cloned()
        .or_else(|| w.auction_item_names.get(&session_top_id).cloned())
        .unwrap_or_default();
    let reserve_price = w
        .auction_reserve_price
        .get(&riggs_auction_id)
        .or_else(|| w.auction_reserve_price.get(&session_top_id))
        .copied()
        .unwrap_or(0);
    MiningSnapshot {
        session_top_id,
        riggs_auction_id,
        item_name,
        reserve_price,
        bids_n,
        revealed_n,
        winner,
        settlement_price: settlement_price,
        empty_round,
        rankings: rk,
        revealed_by_uid,
        round_number,
        streak_snap,
        round_status_snapshot: rm_status,
    }
}

async fn blockchain_chain(State(s): State<AppState>) -> impl IntoResponse {
    let bc = s.blockchain.lock().await;
    let (real_n, latest_real) = mining::chain_real_summaries(&bc);
    let (valid, message) = bc.is_chain_valid();
    Json(json!({
        "difficulty": bc.difficulty,
        "block_count": bc.chain.len(),
        "chain": bc.chain,
        "real_round_block_count": real_n,
        "latest_round_block": latest_real,
        "valid": valid,
        "message": message,
    }))
}

async fn blockchain_validate(State(s): State<AppState>) -> impl IntoResponse {
    let bc = s.blockchain.lock().await;
    let (valid, message) = bc.is_chain_valid();
    Json(json!({ "valid": valid, "message": message }))
}

#[derive(Deserialize)]
struct BlockchainResetBody {
    #[serde(default = "default_blockchain_difficulty")]
    difficulty: u32,
}

fn default_blockchain_difficulty() -> u32 {
    3
}

async fn blockchain_reset(
    State(s): State<AppState>,
    Json(body): Json<BlockchainResetBody>,
) -> impl IntoResponse {
    s.mined_round_blocks.lock().await.clear();
    s.mining_retry_snapshots.lock().await.clear();
    let mut bc = s.blockchain.lock().await;
    bc.difficulty = body.difficulty.max(1);
    bc.mine_genesis();
    Json(json!({
        "ok": true,
        "difficulty": bc.difficulty,
        "block_count": bc.chain.len(),
    }))
}

async fn blockchain_demo_sequence(State(s): State<AppState>) -> impl IntoResponse {
    let mut bc = s.blockchain.lock().await;
    bc.run_classroom_demo_sequence();
    Json(json!({
        "ok": true,
        "difficulty": bc.difficulty,
        "block_count": bc.chain.len(),
        "chain": bc.chain,
    }))
}

async fn blockchain_mine_round(
    State(s): State<AppState>,
    Path(top_id): Path<u32>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let riggs_id = resolve_riggs_for_path(&s, top_id).await;
    let key = (
        top_id,
        riggs_id,
    );
    {
        let mm = s.mined_round_blocks.lock().await;
        if let Some(&idx) = mm.get(&key) {
            let bc = s.blockchain.lock().await;
            let blk = bc.chain.iter().find(|b| b.index == idx);
            let hash = blk.map(|b| b.hash.clone()).unwrap_or_default();
            let valid = blk.map(|_| bc.is_chain_valid().0).unwrap_or(true);
            return Ok(Json(json!({
                "ok": true,
                "idempotent": true,
                "block_index": idx,
                "block_hash": hash,
                "valid": valid,
                "riggs_auction_id": riggs_id,
                "session_top_id": top_id,
            }))
            );
        }
    }

    let snap_retry = {
        let guard = s.mining_retry_snapshots.lock().await;
        guard.get(&riggs_id).cloned()
    };

    let Some(snap) = snap_retry else {
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({"error":"no_mining_snapshot","message":"请先点击 Next round 完成本轮结算；自动挖矿失败后服务端会保留补挖快照"})),
        ));
    };

    match mining::mine_from_snapshot(std::sync::Arc::new(s.clone()), snap.clone()).await {
        mining::MineResult::Mined(ref m) => {
            let valid = {
                let bc = s.blockchain.lock().await;
                bc.is_chain_valid().0
            };
            emit(
                &s,
                Event::RoundBlockMined {
                    session_top_id: snap.session_top_id,
                    riggs_auction_id: snap.riggs_auction_id,
                    round: snap.round_number,
                    block_index: m.block_index,
                    block_hash: m.block_hash.clone(),
                    tx_count: 1usize,
                    valid,
                },
            )
            .await;
            Ok(Json(json!({
                "ok": true,
                "idempotent": false,
                "block_index": m.block_index,
                "block_hash": &m.block_hash,
                "riggs_auction_id": riggs_id,
                "session_top_id": top_id,
                "valid": valid,
            })))
        }
        mining::MineResult::SkippedDuplicate { block_index } => Ok(Json(json!({
            "ok": true,
            "idempotent": true,
            "block_index": block_index,
            "riggs_auction_id": riggs_id,
            "session_top_id": top_id,
        }))),
        mining::MineResult::Failed(ref e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error":"mine_failed","message": e.clone()})),
        )),
    }
}

async fn blockchain_round_status(
    State(s): State<AppState>,
    Path(top_id): Path<u32>,
) -> impl IntoResponse {
    let riggs_id = resolve_riggs_for_path(&s, top_id).await;
    let key = (
        top_id,
        riggs_id,
    );
    let (pending_reveals, bids_n, all_revealed) = {
        let w = s.world.lock().await;
        let p = w.pending_reveals(riggs_id).len();
        let b = *w.bids_per_riggs_auction.get(&riggs_id).unwrap_or(&0);
        let rev = w
            .revealed_bid_ids
            .get(&riggs_id)
            .map(|x| x.len())
            .unwrap_or(0);
        let bids_n_u = b as usize;
        let all_rev = bids_n_u > 0 && rev == bids_n_u;
        (p, b, all_rev)
    };
    let mined_block_index = s.mined_round_blocks.lock().await.get(&key).copied();
    let mining_snapshot_pending = s.mining_retry_snapshots.lock().await.contains_key(&riggs_id);
    let ready_to_pack = mined_block_index.is_none()
        && bids_n > 0
        && pending_reveals == 0
        && all_revealed;
    Json(json!({
        "session_top_id": top_id,
        "current_riggs_auction_id": riggs_id,
        "pending_reveals": pending_reveals,
        "bids_total": bids_n,
        "all_bids_revealed": all_revealed,
        "ready_to_pack": ready_to_pack,
        "mining_snapshot_pending": mining_snapshot_pending,
        "mined_block_index": mined_block_index,
        "already_mined": mined_block_index.is_some(),
    }))
}

async fn blockchain_tamper(State(s): State<AppState>) -> impl IntoResponse {
    let mut bc = s.blockchain.lock().await;
    let changed = bc.tamper_first_bid_preview();
    let (valid, message) = bc.is_chain_valid();
    Json(json!({
        "tampered": changed,
        "valid": valid,
        "message": message,
    }))
}

async fn health() -> impl IntoResponse {
    Json(json!({ "ok": true, "service": "vsbmas-backend" }))
}

async fn l1_bench_handler() -> impl IntoResponse {
    Json(l1::l1_bench())
}

async fn params() -> impl IntoResponse {
    Json(params_summary())
}

#[derive(Deserialize)]
struct CreateAccountReq {
    pub name: Option<String>,
    pub initial_balance: Option<u32>,
}

async fn create_account(State(s): State<AppState>, Json(req): Json<CreateAccountReq>) -> impl IntoResponse {
    let (uid, name, init) = {
        let mut w = s.world.lock().await;
        let house_pp = w.house_pp.clone();
        let (uid, _) = w.house.new_account(&house_pp);
        let init = req.initial_balance.unwrap_or(1000);
        w.house.account_deposit(&house_pp, uid, init).unwrap();
        let mut acc = DemoAccount::new();
        acc.confirm_deposit(&house_pp, init).unwrap();
        w.privates.insert(uid, acc);
        let name = req.name.unwrap_or_else(|| format!("user_{uid}"));
        w.labels.insert(uid, name.clone());
        (uid, name, init)
    };
    emit(&s, Event::AccountCreated {
        id: uid,
        name: name.clone(),
        balance: init,
    })
    .await;
    let (t, av, fr) = {
        let w = s.world.lock().await;
        w.account_balances(uid)
    };
    emit(
        &s,
        Event::AccountBalanceSnapshot {
            user_id: uid,
            total: t,
            available: av,
            frozen: fr,
        },
    )
    .await;
    Json(json!({ "id": uid, "name": name, "balance": init, "available": av, "frozen": fr }))
}

async fn get_account(State(s): State<AppState>, Path(id): Path<u32>) -> impl IntoResponse {
    let w = s.world.lock().await;
    let name = w.labels.get(&id).cloned().unwrap_or_else(|| format!("user_{id}"));
    let (total, available, frozen) = w.account_balances(id);
    Json(json!({
        "id": id,
        "name": name,
        "balance": total,
        "available": available,
        "frozen": frozen
    }))
}

fn ledger_includes_user(v: &serde_json::Value, id: u32) -> bool {
    let ty = v.get("type").and_then(|x| x.as_str()).unwrap_or("");
    match ty {
        "AccountBalanceSnapshot" | "Withdraw" | "BidSubmitted" | "SelfOpened" | "ForceOpened" => {
            v.get("user_id").and_then(|x| x.as_u64()) == Some(id as u64)
        }
        "AccountCreated" | "Deposit" => v.get("id").and_then(|x| x.as_u64()) == Some(id as u64),
        "Settled" => v
            .get("winners")
            .and_then(|w| w.as_array())
            .map(|arr| arr.iter().any(|x| x.as_u64() == Some(id as u64)))
            .unwrap_or(false),
        "VerificationFailed" => v.get("actor").and_then(|x| x.as_u64()) == Some(id as u64),
        "BruteForceProgress" | "BruteForceStopped" => {
            v.get("target_user_id").and_then(|x| x.as_u64()) == Some(id as u64)
        }
        "BruteForceCracked" => v.get("user_id").and_then(|x| x.as_u64()) == Some(id as u64),
        _ => false,
    }
}

async fn account_ledger(State(s): State<AppState>, Path(id): Path<u32>) -> impl IntoResponse {
    let content = tokio::fs::read_to_string(&s.audit.path).await.unwrap_or_default();
    let mut entries = Vec::new();
    for line in content.lines() {
        if line.is_empty() {
            continue;
        }
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(line) {
            if ledger_includes_user(&v, id) {
                entries.push(v);
            }
        }
    }
    Json(json!({ "user_id": id, "count": entries.len(), "entries": entries }))
}

async fn list_accounts(State(s): State<AppState>) -> impl IntoResponse {
    let w = s.world.lock().await;
    let mut ids: Vec<u32> = w.labels.keys().copied().collect();
    ids.sort_unstable();
    let accounts: Vec<_> = ids
        .into_iter()
        .map(|id| {
            let name = w.labels.get(&id).cloned().unwrap_or_default();
            let (total, available, frozen) = w.account_balances(id);
            json!({ "id": id, "name": name, "balance": total, "available": available, "frozen": frozen })
        })
        .collect();
    let count = accounts.len();
    Json(json!({ "count": count, "accounts": accounts }))
}

#[derive(Deserialize)]
struct DepositReq {
    pub amount: u32,
}

async fn deposit(
    State(s): State<AppState>,
    Path(id): Path<u32>,
    Json(r): Json<DepositReq>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let new_balance = {
        let mut w = s.world.lock().await;
        let house_pp = w.house_pp.clone();
        w.house
            .account_deposit(&house_pp, id, r.amount)
            .map_err(|e| (StatusCode::BAD_REQUEST, format!("deposit: {e}")))?;
        let p = w
            .privates
            .get_mut(&id)
            .ok_or((StatusCode::NOT_FOUND, "unknown user".into()))?;
        p.confirm_deposit(&house_pp, r.amount)
            .map_err(|e| (StatusCode::BAD_REQUEST, format!("confirm_deposit: {e}")))?;
        p.public_summary.balance
    };
    emit(&s, Event::Deposit {
        id,
        amount: r.amount,
        new_balance,
    })
    .await;
    let (t, av, fr) = {
        let w = s.world.lock().await;
        w.account_balances(id)
    };
    emit(
        &s,
        Event::AccountBalanceSnapshot {
            user_id: id,
            total: t,
            available: av,
            frozen: fr,
        },
    )
    .await;
    Ok(Json(json!({ "id": id, "deposited": r.amount, "balance": new_balance, "available": av, "frozen": fr })))
}

#[derive(Deserialize)]
struct CreateAuctionReq {
    pub item_name: String,
    pub item_uri: Option<String>,
    pub total_duration_secs: u64,
    pub round_duration_secs: u64,
    pub reserve_price: u32,
}

async fn create_auction(
    State(s): State<AppState>,
    Json(req): Json<CreateAuctionReq>,
) -> impl IntoResponse {
    let (id, item_name, item_uri, reserve_price, total_duration_secs, round_duration_secs) = {
        let mut w = s.world.lock().await;
        let house_pp = w.house_pp.clone();
        let auction_pp = w.auction_pp.clone();
        let id = w.house.new_auction(&house_pp, &auction_pp);
        w.auction_ids.push(id);
        w.auction_item_names.insert(id, req.item_name.clone());
        w.bids_per_riggs_auction.insert(id, 0);
        w.auction_t_start.insert(id, Instant::now());
        w.register_riggs_auction(id, id);
        w.auction_reserve_price.insert(id, req.reserve_price);
        let dl = now_epoch_ms() + req.round_duration_secs.saturating_mul(1000);
        w.phase_deadline_ms.insert(id, dl);
        (
            id,
            req.item_name.clone(),
            req.item_uri.clone(),
            req.reserve_price,
            req.total_duration_secs,
            req.round_duration_secs,
        )
    };
    {
        let cfg = RoundConfig {
            round_duration_secs: round_duration_secs.max(10),
            total_duration_secs: total_duration_secs.max(30),
            streak_threshold: 10,
        };
        let rm = RoundManager::new(cfg, id);
        s.rounds.lock().await.insert(id, rm);
    }
    emit(&s, Event::AuctionCreated {
        id,
        item_name: item_name.clone(),
        item_uri,
        reserve_price,
        total_duration_secs,
        round_duration_secs,
    })
    .await;
    let dl = now_epoch_ms() + round_duration_secs.saturating_mul(1000);
    emit(
        &s,
        Event::PhaseTransition {
            auction_id: id,
            from_phase: "Init".into(),
            to_phase: "BidCollection".into(),
            deadline_epoch_ms: Some(dl),
        },
    )
    .await;
    Json(json!({
        "id": id,
        "item_name": item_name,
        "item_uri": req.item_uri,
        "reserve_price": reserve_price,
        "total_duration_secs": total_duration_secs,
        "round_duration_secs": round_duration_secs,
        "phase": "BidCollection",
        "phase_deadline_ms": dl,
        "current_riggs_auction_id": id,
    }))
}

async fn list_auctions(State(s): State<AppState>) -> impl IntoResponse {
    let w = s.world.lock().await;
    let items: Vec<_> = w
        .auction_ids
        .iter()
        .map(|&id| {
            json!({
                "id": id,
                "item_name": w.auction_item_names.get(&id),
                "phase": w.get_auction_phase(id),
            })
        })
        .collect();
    Json(json!({ "auctions": items, "count": items.len() }))
}

async fn get_auction(State(s): State<AppState>, Path(id): Path<u32>) -> impl IntoResponse {
    let riggs = resolve_riggs_for_path(&s, id).await;
    let w = s.world.lock().await;
    let item = w
        .auction_item_names
        .get(&riggs)
        .or_else(|| w.auction_item_names.get(&id))
        .cloned()
        .unwrap_or_default();
    let phase = w.get_auction_phase(riggs);
    let deadline = w.phase_deadline_ms.get(&riggs).copied();
    let top = w.riggs_session_top.get(&riggs).copied().unwrap_or(id);
    Json(json!({
        "id": id,
        "resolved_riggs_auction_id": riggs,
        "session_top_id": top,
        "item_name": item,
        "phase": phase,
        "phase_deadline_ms": deadline,
    }))
}

async fn get_rankings(State(s): State<AppState>, Path(id): Path<u32>) -> impl IntoResponse {
    let riggs = resolve_riggs_for_path(&s, id).await;
    let w = s.world.lock().await;
    let r = w.bid_rankings_snapshot(riggs);
    Json(json!({
        "auction_id": riggs,
        "highest": { "user_id": r.highest_user_id, "amount": r.highest_amount },
        "second_highest": { "user_id": r.second_user_id, "amount": r.second_amount },
    }))
}

#[derive(Deserialize)]
struct SetPhaseReq {
    pub phase: String,
    #[serde(default)]
    pub display_duration_secs: Option<u64>,
}

async fn set_phase(
    State(s): State<AppState>,
    Path(top_id): Path<u32>,
    Json(req): Json<SetPhaseReq>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let riggs = {
        let rounds = s.rounds.lock().await;
        rounds
            .get(&top_id)
            .map(|rm| rm.current_riggs_auction_id)
            .ok_or((StatusCode::NOT_FOUND, "unknown session / auction".into()))?
    };
    let from = {
        let w = s.world.lock().await;
        w.get_auction_phase(riggs)
    };
    let dl = req
        .display_duration_secs
        .map(|d| now_epoch_ms() + d.saturating_mul(1000));
    {
        let mut w = s.world.lock().await;
        w.set_teacher_phase(riggs, &req.phase);
        if let Some(d) = dl {
            w.phase_deadline_ms.insert(riggs, d);
        }
    }
    emit(
        &s,
        Event::PhaseTransition {
            auction_id: riggs,
            from_phase: from,
            to_phase: req.phase.clone(),
            deadline_epoch_ms: dl,
        },
    )
    .await;

    if req.phase == "BidSelfOpening" {
        let intents: Vec<(u32, u32, u32)> = {
            let mut w = s.world.lock().await;
            let keys: Vec<(u32, u32)> = w
                .pending_self_open
                .keys()
                .filter(|(aid, _)| *aid == riggs)
                .copied()
                .collect();
            let mut v = Vec::new();
            for (aid, uid) in keys {
                if let Some(bid) = w.pending_self_open.remove(&(aid, uid)) {
                    v.push((aid, uid, bid));
                }
            }
            v
        };
        for (_aid, uid, bid) in intents {
            let res = {
                let mut w = s.world.lock().await;
                world_run_self_open(&mut w, riggs, uid, bid)
            };
            match res {
                Ok((ov, rankings)) => {
                    emit(
                        &s,
                        Event::SelfOpened {
                            auction_id: riggs,
                            user_id: uid,
                            bid_revealed: bid,
                            opening: ov.clone(),
                            rankings: Some(rankings.clone()),
                        },
                    )
                    .await;
                    let (t, av, fr) = {
                        let w = s.world.lock().await;
                        w.account_balances(uid)
                    };
                    emit(
                        &s,
                        Event::AccountBalanceSnapshot {
                            user_id: uid,
                            total: t,
                            available: av,
                            frozen: fr,
                        },
                    )
                    .await;
                }
                Err(e) => tracing::warn!(user_id = uid, err = %e, "batch self_open intent failed"),
            }
        }

        let uids: Vec<u32> = {
            let w = s.world.lock().await;
            w.pending_reveals(riggs)
                .into_iter()
                .map(|(u, _)| u)
                .collect()
        };
        let mut force_emissions: Vec<(u32, u32, TcOpeningView, BidRankings)> = Vec::new();
        for uid in uids {
            // v4.1：阶段批处理也走幂等守卫，避免多次 BidSelfOpening 触发重复 RSW。
            match try_claim_force_open(&s, riggs, uid).await {
                ClaimOutcome::AlreadyRevealed(_) => {
                    tracing::info!(auction_id = riggs, user_id = uid, "batch force_open: already revealed, skip");
                    continue;
                }
                ClaimOutcome::InFlight => {
                    tracing::info!(auction_id = riggs, user_id = uid, "batch force_open: already in flight, skip");
                    continue;
                }
                ClaimOutcome::Fresh => {}
            }
            match apply_force_open_honest_emit_progress(&s, riggs, uid).await {
                Ok((bid_revealed, opening, ms)) => {
                    {
                        let mut w = s.world.lock().await;
                        w.record_reveal(riggs, uid, bid_revealed);
                    }
                    let ov = tc_opening_view_with_meta(&opening, tc_force_meta(Some(ms), Some(true)));
                    let rk = {
                        let w = s.world.lock().await;
                        w.bid_rankings_snapshot(riggs)
                    };
                    store_force_open_cache(
                        &s,
                        riggs,
                        uid,
                        ForceOpenCached {
                            bid_revealed,
                            opening: ov.clone(),
                            rankings: rk.clone(),
                            computation_ms: ms,
                            trigger: "teacher".into(),
                        },
                    )
                    .await;
                    release_force_open_claim(&s, riggs, uid).await;
                    force_emissions.push((uid, bid_revealed, ov, rk));
                }
                Err(e) => {
                    release_force_open_claim(&s, riggs, uid).await;
                    tracing::warn!(
                        auction_id = riggs,
                        user_id = uid,
                        err = %e,
                        "set_phase force_open failed",
                    );
                }
            }
        }
        for (uid, bid_revealed, opening, rankings) in force_emissions {
            emit(
                &s,
                Event::ForceOpened {
                    auction_id: riggs,
                    user_id: uid,
                    bid_revealed: Some(bid_revealed),
                    opening: opening.clone(),
                    rankings: Some(rankings.clone()),
                },
            )
            .await;
            let (t, av, fr) = {
                let w = s.world.lock().await;
                w.account_balances(uid)
            };
            emit(
                &s,
                Event::AccountBalanceSnapshot {
                    user_id: uid,
                    total: t,
                    available: av,
                    frozen: fr,
                },
            )
            .await;
        }
    }

    Ok(Json(json!({
        "ok": true,
        "riggs_auction_id": riggs,
        "session_top_id": top_id,
        "phase": req.phase,
        "phase_deadline_ms": dl,
    })))
}

#[derive(Deserialize)]
struct BidReq {
    pub user_id: u32,
    pub amount: u32,
}

async fn bid(
    State(s): State<AppState>,
    Path(auction_id): Path<u32>,
    Json(req): Json<BidReq>,
) -> Response {
    let riggs = resolve_riggs_for_path(&s, auction_id).await;
    let phase = {
        let w = s.world.lock().await;
        w.get_auction_phase(riggs)
    };
    if phase != "BidCollection" {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "wrong_phase",
                "phase": phase,
                "expected": "BidCollection"
            })),
        )
            .into_response();
    }

    let reserve = {
        let w = s.world.lock().await;
        w.auction_reserve_price.get(&riggs).copied().unwrap_or(0)
    };
    if req.amount < reserve {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "bid_below_reserve",
                "min": reserve,
                "bid": req.amount
            })),
        )
            .into_response();
    }

    let available = {
        let w = s.world.lock().await;
        w.account_balances(req.user_id).1
    };
    if req.amount > available {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "bid_exceeds_balance",
                "available": available,
                "bid": req.amount
            })),
        )
            .into_response();
    }

    let prev_high = {
        let w = s.world.lock().await;
        let top_id = w.riggs_session_top.get(&riggs).copied().unwrap_or(riggs);
        w.prev_round_high_bid.get(&top_id).copied().unwrap_or(0)
    };
    if prev_high > 0 && req.amount <= prev_high {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "bid_not_higher_than_prev_round",
                "min_exclusive": prev_high,
                "bid": req.amount
            })),
        )
            .into_response();
    }

    // Part B1：彻底 ZK gating —— 先 propose_bid，再强制对 `bid >= reserve` 与
    // `bid > prev_round_high_bid` 生成 Bulletproofs 证明并 verify；任一失败立即 400，
    // 绝不调用 `account_bid`。这样即使上层明文 fast-path 被绕过（或移除），verifier
    // 层面仍保证非法 bid 无法落账。
    let (bid_view, t_prove_ms, verify_ms, user_id, constraint_proofs) = {
        let mut w = s.world.lock().await;
        let house_pp = w.house_pp.clone();
        let auction_pp = w.auction_pp.clone();

        let private = match w.privates.get(&req.user_id).cloned() {
            Some(p) => p,
            None => {
                return (
                    StatusCode::NOT_FOUND,
                    Json(json!({
                        "error": "unknown_user",
                        "user_id": req.user_id
                    })),
                )
                    .into_response();
            }
        };

        let t0 = std::time::Instant::now();
        let (bid_proposal, opening) = match private.propose_bid(&mut w.rng, &house_pp, &auction_pp, req.amount) {
            Ok(x) => x,
            Err(e) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({
                        "error": "propose_bid_failed",
                        "detail": format!("{e:?}"),
                        "bid": req.amount
                    })),
                )
                    .into_response();
            }
        };
        let t_prove_ms = t0.elapsed().as_millis() as u64;

        // === Bulletproofs 附加约束（verifier-enforced gating）===
        let opening_ped = opening.get_ped_opening();
        let comm_bid_ped = bid_proposal.comm_bid.ped_comm.clone();

        let reserve_proof = match prove_bid_at_least(
            &mut w.rng,
            &house_pp,
            &auction_pp,
            &comm_bid_ped,
            req.amount,
            reserve,
            &opening_ped,
        ) {
            Ok(p) => p,
            Err(e) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({
                        "error": "bid_constraint_prove_failed",
                        "which": "reserve",
                        "detail": e,
                        "reserve": reserve,
                        "bid": req.amount,
                    })),
                )
                    .into_response();
            }
        };
        let reserve_ok = verify_bid_at_least(
            &house_pp,
            &auction_pp,
            &comm_bid_ped,
            reserve,
            &reserve_proof,
        )
        .unwrap_or(false);
        if !reserve_ok {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "bid_constraint_verify_failed",
                    "which": "reserve",
                    "reserve": reserve,
                    "bid": req.amount,
                })),
            )
                .into_response();
        }
        let (rp_hex, rp_size) = range_proof_hex(&reserve_proof);

        let (prev_hex, prev_size, prev_ok_field) = if prev_high > 0 {
            let prev_proof = match prove_bid_at_least(
                &mut w.rng,
                &house_pp,
                &auction_pp,
                &comm_bid_ped,
                req.amount,
                prev_high + 1,
                &opening_ped,
            ) {
                Ok(p) => p,
                Err(e) => {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(json!({
                            "error": "bid_constraint_prove_failed",
                            "which": "prev_round_high_bid",
                            "detail": e,
                            "prev_round_high_bid": prev_high,
                            "bid": req.amount,
                        })),
                    )
                        .into_response();
                }
            };
            let prev_ok = verify_bid_at_least(
                &house_pp,
                &auction_pp,
                &comm_bid_ped,
                prev_high + 1,
                &prev_proof,
            )
            .unwrap_or(false);
            if !prev_ok {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({
                        "error": "bid_constraint_verify_failed",
                        "which": "prev_round_high_bid",
                        "prev_round_high_bid": prev_high,
                        "bid": req.amount,
                    })),
                )
                    .into_response();
            }
            let (h, sz) = range_proof_hex(&prev_proof);
            (Some(h), Some(sz), Some(true))
        } else {
            (None, None, None)
        };

        let constraint_proofs = Some(BidConstraintProofs {
            reserve_price: reserve,
            reserve_proof_hex: rp_hex,
            reserve_proof_size: rp_size,
            reserve_verify_ok: true,
            prev_round_high_bid: if prev_high > 0 { Some(prev_high) } else { None },
            prev_proof_hex: prev_hex,
            prev_proof_size: prev_size,
            prev_verify_ok: prev_ok_field,
        });

        // === gating 通过 → 落账 ===
        let t_v0 = std::time::Instant::now();
        let new_bid_id = *w.bids_per_riggs_auction.get(&riggs).unwrap_or(&0);
        if let Err(e) = w
            .house
            .account_bid(&house_pp, &auction_pp, riggs, req.user_id, &bid_proposal)
        {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "account_bid_failed",
                    "detail": format!("{e:?}"),
                    "bid": req.amount
                })),
            )
                .into_response();
        }
        let verify_ms = t_v0.elapsed().as_millis() as u128;

        if let Some(p) = w.privates.get_mut(&req.user_id) {
            let _ = p.confirm_bid(
                &house_pp,
                &auction_pp,
                riggs,
                req.amount,
                &bid_proposal,
                &opening,
            );
        }

        *w.bids_per_riggs_auction.entry(riggs).or_insert(0) += 1;
        w.bid_index.insert((riggs, req.user_id), new_bid_id);
        let x = bid_proposal.comm_bid.tc_comm.x.clone();
        w.bid_rsw_base.insert((riggs, req.user_id), x);
        w.bid_rsw_tc
            .insert((riggs, req.user_id), bid_proposal.comm_bid.tc_comm.clone());

        let bid_view = bid_proposal_view(&bid_proposal);
        (bid_view, t_prove_ms, verify_ms, req.user_id, constraint_proofs)
    };

    emit(&s, Event::BidSubmitted {
        auction_id: riggs,
        user_id,
        prove_ms: t_prove_ms as u128,
        verify_ms,
        bid_view: bid_view.clone(),
        constraint_proofs: constraint_proofs.clone(),
    })
    .await;

    let (t, av, fr) = {
        let w = s.world.lock().await;
        w.account_balances(user_id)
    };
    emit(
        &s,
        Event::AccountBalanceSnapshot {
            user_id,
            total: t,
            available: av,
            frozen: fr,
        },
    )
    .await;

    Json(json!({
        "ok": true,
        "prove_ms": t_prove_ms,
        "bid_view": bid_view,
        "constraint_proofs": constraint_proofs,
        "available": av,
        "frozen": fr,
    }))
    .into_response()
}

#[derive(Deserialize)]
struct WithdrawReq {
    pub user_id: u32,
    pub amount: u32,
}

async fn withdraw(
    State(s): State<AppState>,
    Path(auction_id): Path<u32>,
    Json(r): Json<WithdrawReq>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    {
        let mut w = s.world.lock().await;
        let house_pp = w.house_pp.clone();
        let private = w
            .privates
            .get(&r.user_id)
            .ok_or((StatusCode::NOT_FOUND, "unknown user".into()))?
            .clone();
        let proof = private
            .propose_withdrawal(&mut w.rng, &house_pp, r.amount)
            .map_err(|e| (StatusCode::BAD_REQUEST, format!("propose_withdrawal: {e}")))?;
        w.house
            .account_withdrawal(&house_pp, r.user_id, r.amount, &proof)
            .map_err(|e| (StatusCode::BAD_REQUEST, format!("account_withdrawal: {e}")))?;
        w.privates
            .get_mut(&r.user_id)
            .unwrap()
            .confirm_withdrawal(&house_pp, r.amount)
            .map_err(|e| (StatusCode::BAD_REQUEST, format!("confirm_withdrawal: {e}")))?;
    }
    emit(&s, Event::Withdraw {
        user_id: r.user_id,
        amount: r.amount,
    })
    .await;
    let (t, av, fr) = {
        let w = s.world.lock().await;
        w.account_balances(r.user_id)
    };
    emit(
        &s,
        Event::AccountBalanceSnapshot {
            user_id: r.user_id,
            total: t,
            available: av,
            frozen: fr,
        },
    )
    .await;
    Ok(Json(
        json!({ "auction_id": auction_id, "user_id": r.user_id, "withdrawn": r.amount, "ok": true, "available": av, "frozen": fr }),
    ))
}

#[derive(Deserialize)]
struct SelfOpenReq {
    pub user_id: u32,
    pub bid: u32,
}

async fn self_open(
    State(s): State<AppState>,
    Path(auction_id): Path<u32>,
    Json(r): Json<SelfOpenReq>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let riggs = resolve_riggs_for_path(&s, auction_id).await;
    let ph = {
        let w = s.world.lock().await;
        w.get_auction_phase(riggs)
    };
    if ph != "BidSelfOpening" && ph != "BidForceOpening" {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("self-open only after teacher opens BidSelfOpening (now: {ph})"),
        ));
    }

    let (ov, rankings) = {
        let mut w = s.world.lock().await;
        world_run_self_open(&mut w, riggs, r.user_id, r.bid)
            .map_err(|e| (StatusCode::BAD_REQUEST, e))?
    };

    emit(&s, Event::SelfOpened {
        auction_id: riggs,
        user_id: r.user_id,
        bid_revealed: r.bid,
        opening: ov.clone(),
        rankings: Some(rankings.clone()),
    })
    .await;

    let (t, av, fr) = {
        let w = s.world.lock().await;
        w.account_balances(r.user_id)
    };
    emit(
        &s,
        Event::AccountBalanceSnapshot {
            user_id: r.user_id,
            total: t,
            available: av,
            frozen: fr,
        },
    )
    .await;

    Ok(Json(json!({
        "ok": true,
        "auction_id": riggs,
        "user_id": r.user_id,
        "bid": r.bid,
        "opening": ov,
        "rankings": rankings,
        "available": av,
        "frozen": fr,
    })))
}

#[derive(Deserialize)]
struct SelfOpenIntentReq {
    pub user_id: u32,
    pub bid: u32,
}

async fn self_open_intent(
    State(s): State<AppState>,
    Path(auction_id): Path<u32>,
    Json(r): Json<SelfOpenIntentReq>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let riggs = resolve_riggs_for_path(&s, auction_id).await;
    let ph = {
        let w = s.world.lock().await;
        w.get_auction_phase(riggs)
    };
    if ph == "BidCollection" {
        {
            let mut w = s.world.lock().await;
            w.pending_self_open.insert((riggs, r.user_id), r.bid);
        }
        return Ok(Json(json!({
            "ok": true,
            "mode": "queued",
            "auction_id": riggs,
            "user_id": r.user_id,
            "bid": r.bid
        })));
    }
    if ph == "BidSelfOpening" {
        // v4.1（问题 3）：只有在 BidCollection 阶段预约过的用户才允许在
        // BidSelfOpening 阶段立即揭示；未预约者必须走 force-open 流程。
        let already_scheduled = {
            let w = s.world.lock().await;
            w.pending_self_open.contains_key(&(riggs, r.user_id))
        };
        if !already_scheduled {
            return Err((
                StatusCode::BAD_REQUEST,
                r#"{"error":"must_schedule_in_collection","message":"Schedule self-open during BidCollection; in BidSelfOpening only scheduled bids are revealed"}"#.into(),
            ));
        }
        let res = {
            let mut w = s.world.lock().await;
            world_run_self_open(&mut w, riggs, r.user_id, r.bid)
        };
        let (ov, rankings) = match res {
            Ok(x) => x,
            Err(e) => {
                return Err((
                    StatusCode::BAD_REQUEST,
                    format!(
                        r#"{{"error":"self_open_failed","message":"{}"}}"#,
                        e.replace('"', "'")
                    ),
                ));
            }
        };
        emit(
            &s,
            Event::SelfOpened {
                auction_id: riggs,
                user_id: r.user_id,
                bid_revealed: r.bid,
                opening: ov.clone(),
                rankings: Some(rankings.clone()),
            },
        )
        .await;
        let (t, av, fr) = {
            let w = s.world.lock().await;
            w.account_balances(r.user_id)
        };
        emit(
            &s,
            Event::AccountBalanceSnapshot {
                user_id: r.user_id,
                total: t,
                available: av,
                frozen: fr,
            },
        )
        .await;
        return Ok(Json(json!({
            "ok": true,
            "mode": "immediate",
            "auction_id": riggs,
            "user_id": r.user_id,
            "bid": r.bid,
            "opening": ov,
            "rankings": rankings,
            "available": av,
            "frozen": fr,
        })));
    }
    Err((
        StatusCode::BAD_REQUEST,
        format!(
            "self_open_intent: use BidCollection or BidSelfOpening (now: {ph})"
        ),
    ))
}

#[derive(Deserialize)]
struct ReleaseLoserReq {
    pub user_id: u32,
}

async fn release_loser(
    State(s): State<AppState>,
    Path(auction_id): Path<u32>,
    Json(r): Json<ReleaseLoserReq>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let riggs = resolve_riggs_for_path(&s, auction_id).await;
    let released = {
        let mut w = s.world.lock().await;
        w.try_release_loser_escrow(riggs, r.user_id)
            .map_err(|e| (StatusCode::BAD_REQUEST, e))?
    };
    let (t, av, fr) = {
        let w = s.world.lock().await;
        w.account_balances(r.user_id)
    };
    emit(
        &s,
        Event::AccountBalanceSnapshot {
            user_id: r.user_id,
            total: t,
            available: av,
            frozen: fr,
        },
    )
    .await;
    Ok(Json(json!({
        "ok": true,
        "auction_id": riggs,
        "released": released,
        "available": av,
        "frozen": fr,
    })))
}

#[derive(Deserialize)]
struct ForceOpenReq {
    pub user_id: u32,
}

async fn force_open(
    State(s): State<AppState>,
    Path(auction_id): Path<u32>,
    Json(r): Json<ForceOpenReq>,
) -> Result<Response, (StatusCode, String)> {
    let riggs = resolve_riggs_for_path(&s, auction_id).await;
    let ph = {
        let w = s.world.lock().await;
        w.get_auction_phase(riggs)
    };
    if ph != "BidForceOpening" && ph != "BidSelfOpening" {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                r#"{{"error":"phase_not_allowed","message":"force-open allowed in BidSelfOpening/BidForceOpening (now: {ph})"}}"#
            ),
        ));
    }

    // v4.1：幂等守卫 —— 重复点击/阶段二次触发时，不再重跑 ~131s 的 RSW。
    match try_claim_force_open(&s, riggs, r.user_id).await {
        ClaimOutcome::AlreadyRevealed(Some(c)) => {
            let (t, av, fr) = {
                let w = s.world.lock().await;
                w.account_balances(r.user_id)
            };
            return Ok(Json(json!({
                "ok": true,
                "cached": true,
                "trigger": c.trigger,
                "auction_id": riggs,
                "user_id": r.user_id,
                "bid_revealed": c.bid_revealed,
                "opening": c.opening,
                "rankings": c.rankings,
                "computation_ms": c.computation_ms,
                "available": av,
                "frozen": fr,
            }))
            .into_response());
        }
        ClaimOutcome::AlreadyRevealed(None) => {
            let (rankings, total, av, fr) = {
                let w = s.world.lock().await;
                let rk = w.bid_rankings_snapshot(riggs);
                let (t, a, f) = w.account_balances(r.user_id);
                (rk, t, a, f)
            };
            return Ok(Json(json!({
                "ok": true,
                "cached": true,
                "already_revealed": true,
                "auction_id": riggs,
                "user_id": r.user_id,
                "rankings": rankings,
                "total": total,
                "available": av,
                "frozen": fr,
            }))
            .into_response());
        }
        ClaimOutcome::InFlight => {
            let body = json!({
                "error": "force_open_in_progress",
                "message": "another force-open for this (auction, user) is running; watch ForceOpenProgress events",
                "auction_id": riggs,
                "user_id": r.user_id,
            });
            return Ok((StatusCode::CONFLICT, Json(body)).into_response());
        }
        ClaimOutcome::Fresh => {}
    }

    let res = apply_force_open_honest_emit_progress(&s, riggs, r.user_id).await;
    let (bid_revealed, opening, ms) = match res {
        Ok(v) => v,
        Err(e) => {
            release_force_open_claim(&s, riggs, r.user_id).await;
            return Err((
                StatusCode::BAD_REQUEST,
                format!(r#"{{"error":"force_open_failed","message":"{}"}}"#, e.replace('"', "'")),
            ));
        }
    };
    {
        let mut w = s.world.lock().await;
        w.record_reveal(riggs, r.user_id, bid_revealed);
    }
    let rankings = {
        let w = s.world.lock().await;
        w.bid_rankings_snapshot(riggs)
    };
    let opening_view = tc_opening_view_with_meta(&opening, tc_force_meta(Some(ms), Some(true)));

    store_force_open_cache(
        &s,
        riggs,
        r.user_id,
        ForceOpenCached {
            bid_revealed,
            opening: opening_view.clone(),
            rankings: rankings.clone(),
            computation_ms: ms,
            trigger: "teacher".into(),
        },
    )
    .await;
    release_force_open_claim(&s, riggs, r.user_id).await;

    emit(
        &s,
        Event::ForceOpened {
            auction_id: riggs,
            user_id: r.user_id,
            bid_revealed: Some(bid_revealed),
            opening: opening_view.clone(),
            rankings: Some(rankings.clone()),
        },
    )
    .await;

    let (t, av, fr) = {
        let w = s.world.lock().await;
        w.account_balances(r.user_id)
    };
    emit(
        &s,
        Event::AccountBalanceSnapshot {
            user_id: r.user_id,
            total: t,
            available: av,
            frozen: fr,
        },
    )
    .await;

    Ok(Json(json!({
        "ok": true,
        "auction_id": riggs,
        "user_id": r.user_id,
        "bid_revealed": bid_revealed,
        "opening": opening_view,
        "rankings": rankings,
        "available": av,
        "frozen": fr,
        "computation_ms": ms,
    }))
    .into_response())
}

#[derive(Deserialize, Default)]
struct AdvanceQuery {
    #[serde(default)]
    pub force: Option<bool>,
}

#[derive(Deserialize, Default)]
struct AdvanceReq {
    pub k: Option<usize>,
}

async fn pending_users(State(s): State<AppState>, Path(id): Path<u32>) -> impl IntoResponse {
    let riggs = resolve_riggs_for_path(&s, id).await;
    let uids: Vec<u32> = {
        let w = s.world.lock().await;
        w.pending_reveals(riggs)
            .into_iter()
            .map(|(u, _)| u)
            .collect()
    };
    Json(json!({
        "auction_id": riggs,
        "user_ids": uids
    }))
}

async fn can_advance(State(s): State<AppState>, Path(id): Path<u32>) -> impl IntoResponse {
    let riggs = resolve_riggs_for_path(&s, id).await;
    let (pending_n, phase) = {
        let w = s.world.lock().await;
        let n = w.pending_reveals(riggs).len();
        let ph = w.get_auction_phase(riggs);
        (n, ph)
    };
    let session_status = {
        let rounds = s.rounds.lock().await;
        rounds.get(&id).map(|rm| match rm.status {
            MultiRoundStatus::Active => "Active",
            MultiRoundStatus::Complete => "Complete",
        })
    };
    let (can, reason) = if session_status == Some("Complete") {
        (false, "session already Complete".to_string())
    } else if phase == "BidCollection" {
        (false, "still in BidCollection; click Open bid first".to_string())
    } else if pending_n > 0 {
        (false, format!("{pending_n} bid(s) still unrevealed; wait for force-open"))
    } else {
        (true, "ready to advance to next round".to_string())
    };
    Json(json!({
        "session_top_id": id,
        "current_riggs_auction_id": riggs,
        "phase": phase,
        "pending_reveals": pending_n,
        "session_status": session_status,
        "can_advance": can,
        "reason": reason
    }))
}

async fn advance_round(
    State(s): State<AppState>,
    Path(top_id): Path<u32>,
    Query(q): Query<AdvanceQuery>,
    Json(req): Json<AdvanceReq>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let force = q.force.unwrap_or(false);
    {
        let rounds = s.rounds.lock().await;
        if let Some(rm) = rounds.get(&top_id) {
            if rm.status == MultiRoundStatus::Complete && !force {
                return Ok(Json(json!({
                    "top_id": top_id,
                    "status": "Complete",
                    "msg": "already complete"
                })));
            }
        }
    }

    let riggs_id = {
        let rounds = s.rounds.lock().await;
        let rm = rounds
            .get(&top_id)
            .ok_or((StatusCode::NOT_FOUND, "no such top id".into()))?;
        rm.current_riggs_auction_id
    };

    let k = req.k.unwrap_or(0);

    let uids: Vec<u32> = {
        let w = s.world.lock().await;
        w.pending_reveals(riggs_id)
            .into_iter()
            .map(|(u, _)| u)
            .collect()
    };
    let mut force_emissions: Vec<(
        u32,
        u32,
        u32,
        vsbmas_core::serialize::TcOpeningView,
        vsbmas_core::events::BidRankings,
    )> = Vec::new();
    for uid in uids {
        // v4.1：advance_round 的兜底 force-open 也走幂等守卫。
        match try_claim_force_open(&s, riggs_id, uid).await {
            ClaimOutcome::AlreadyRevealed(_) => continue,
            ClaimOutcome::InFlight => continue,
            ClaimOutcome::Fresh => {}
        }
        match apply_force_open_honest_emit_progress(&s, riggs_id, uid).await {
            Ok((bid_revealed, opening, ms)) => {
                {
                    let mut w = s.world.lock().await;
                    w.record_reveal(riggs_id, uid, bid_revealed);
                }
                let ov = tc_opening_view_with_meta(&opening, tc_force_meta(Some(ms), Some(true)));
                let rk = {
                    let w = s.world.lock().await;
                    w.bid_rankings_snapshot(riggs_id)
                };
                store_force_open_cache(
                    &s,
                    riggs_id,
                    uid,
                    ForceOpenCached {
                        bid_revealed,
                        opening: ov.clone(),
                        rankings: rk.clone(),
                        computation_ms: ms,
                        trigger: "teacher".into(),
                    },
                )
                .await;
                release_force_open_claim(&s, riggs_id, uid).await;
                force_emissions.push((riggs_id, uid, bid_revealed, ov, rk));
            }
            Err(e) => {
                release_force_open_claim(&s, riggs_id, uid).await;
                tracing::warn!(
                    auction_id = riggs_id,
                    user_id = uid,
                    err = %e,
                    "advance_round: force_open fallback failed",
                );
            }
        }
    }
    for (aid, uid, bid_revealed, opening, rankings) in &force_emissions {
        emit(
            &s,
            Event::ForceOpened {
                auction_id: *aid,
                user_id: *uid,
                bid_revealed: Some(*bid_revealed),
                opening: opening.clone(),
                rankings: Some(rankings.clone()),
            },
        )
        .await;
    }

    let (winner, price, bids_n, empty_round) = {
        let mut w = s.world.lock().await;
        let house_pp = w.house_pp.clone();
        let auction_pp = w.auction_pp.clone();
        let bids_n = w
            .bids_per_riggs_auction
            .get(&riggs_id)
            .copied()
            .unwrap_or(0);
        let revealed_n = w
            .revealed_bid_ids
            .get(&riggs_id)
            .map(|s| s.len() as u32)
            .unwrap_or(0);

        if revealed_n == 0 {
            (None, 0u32, bids_n, true)
        } else if revealed_n > k as u32 {
            let (price, winners) = w
                .house
                .complete_kplusone_price_auction(&house_pp, &auction_pp, riggs_id, k)
                .unwrap_or((0, vec![]));
            if let Err(e) = w.finalize_private_after_settlement(riggs_id, price, &winners) {
                tracing::warn!(err = %e, "finalize_private_after_settlement");
            }
            (winners.first().copied(), price, bids_n, false)
        } else {
            (None, 0u32, bids_n, true)
        }
    };

    // 真实轮结算完成后、RoundManager 推进下一轮之前：打包本轮 DemoBlockchain 区块（幂等）。
    if bids_n > 0 {
        let rm_meta = {
            let rounds = s.rounds.lock().await;
            rounds
                .get(&top_id)
                .map(|rm| (rm.current_round, rm.streak, rm.status.clone()))
        };
        if let Some((round_number, streak_snap, rm_status)) = rm_meta {
            let snapshot = {
                let w = s.world.lock().await;
                let rk = w.bid_rankings_snapshot(riggs_id);
                build_mining_snapshot(
                    &w,
                    top_id,
                    riggs_id,
                    winner,
                    price,
                    bids_n,
                    empty_round,
                    round_number,
                    streak_snap,
                    rm_status,
                    rk,
                )
            };
            match mining::mine_from_snapshot(std::sync::Arc::new(s.clone()), snapshot.clone()).await {
                mining::MineResult::Mined(ref m) => {
                    let valid = {
                        let bc = s.blockchain.lock().await;
                        bc.is_chain_valid().0
                    };
                    emit(
                        &s,
                        Event::RoundBlockMined {
                            session_top_id: snapshot.session_top_id,
                            riggs_auction_id: snapshot.riggs_auction_id,
                            round: snapshot.round_number,
                            block_index: m.block_index,
                            block_hash: m.block_hash.clone(),
                            tx_count: 1usize,
                            valid,
                        },
                    )
                    .await;
                }
                mining::MineResult::Failed(ref e) => {
                    tracing::warn!(
                        riggs_auction_id = riggs_id,
                        err = %e,
                        "advance_round: demo chain mining failed; snapshot kept for POST /mine-round retry",
                    );
                    s.mining_retry_snapshots
                        .lock()
                        .await
                        .insert(riggs_id, snapshot);
                }
                mining::MineResult::SkippedDuplicate { .. } => {}
            }
        } else {
            tracing::warn!(
                session_top_id = top_id,
                riggs_auction_id = riggs_id,
                "advance_round: missing RoundManager snapshot; skip round-chain mining",
            );
        }
    }

    if empty_round {
        emit(
            &s,
            Event::Settled {
                auction_id: riggs_id,
                price: 0,
                winners: vec![],
            },
        )
        .await;
        emit(
            &s,
            Event::VerificationFailed {
                actor: 0,
                auction_id: Some(riggs_id),
                reason: "no revealed bids after force-open fallback".into(),
                category: "empty-round".into(),
            },
        )
        .await;
    }

    let round_duration_secs = {
        let rounds = s.rounds.lock().await;
        rounds
            .get(&top_id)
            .map(|rm| rm.cfg.round_duration_secs)
            .unwrap_or(60)
    };

    let (new_round, streak, riggs_out, status_str, new_riggs_id, last_price, leader_out) = {
        let mut rounds = s.rounds.lock().await;
        let rm = rounds
            .get_mut(&top_id)
            .ok_or((StatusCode::NOT_FOUND, "no such top id".into()))?;
        if rm.status == MultiRoundStatus::Complete && !force {
            return Ok(Json(json!({
                "top_id": top_id,
                "status": "Complete",
                "msg": "already complete"
            })));
        }
        if force && rm.status == MultiRoundStatus::Complete {
            rm.status = MultiRoundStatus::Active;
        }
        let need_next = if force {
            rm.force_advance_round(winner, price, bids_n);
            true
        } else {
            rm.on_round_complete(winner, price, bids_n).is_some()
        };
        let mut new_riggs: Option<u32> = None;
        if need_next {
            let mut w = s.world.lock().await;
            // Part B：在开启新一轮 Riggs 拍卖前，快照本轮最高揭示出价，供下一轮 `bid > prev_round_max` ZK 约束使用。
            let prev_high = w
                .revealed_rankings
                .get(&riggs_id)
                .and_then(|v| v.first().map(|(_, amt)| *amt))
                .unwrap_or(0);
            w.prev_round_high_bid.insert(top_id, prev_high);
            let house_pp = w.house_pp.clone();
            let auction_pp = w.auction_pp.clone();
            let new_id = w.house.new_auction(&house_pp, &auction_pp);
            w.auction_ids.push(new_id);
            w.bids_per_riggs_auction.insert(new_id, 0);
            w.auction_t_start.insert(new_id, Instant::now());
            w.register_riggs_auction(new_id, top_id);
            if let Some(name) = w.auction_item_names.get(&top_id).cloned() {
                w.auction_item_names.insert(new_id, name);
            }
            let rp = w.auction_reserve_price.get(&top_id).copied().unwrap_or(0);
            w.auction_reserve_price.insert(new_id, rp);
            let dl = now_epoch_ms() + round_duration_secs.saturating_mul(1000);
            w.phase_deadline_ms.insert(new_id, dl);
            rm.current_riggs_auction_id = new_id;
            new_riggs = Some(new_id);
        }
        let status_str = match rm.status {
            MultiRoundStatus::Active => "Active",
            MultiRoundStatus::Complete => "Complete",
        };
        (
            rm.current_round,
            rm.streak,
            rm.current_riggs_auction_id,
            status_str,
            new_riggs,
            price,
            rm.current_leader,
        )
    };

    if let Some(nr) = new_riggs_id {
        let dl = now_epoch_ms() + round_duration_secs.saturating_mul(1000);
        emit(
            &s,
            Event::PhaseTransition {
                auction_id: nr,
                from_phase: "Complete".into(),
                to_phase: "BidCollection".into(),
                deadline_epoch_ms: Some(dl),
            },
        )
        .await;
    }

    emit(
        &s,
        Event::RoundAdvanced {
            auction_id: top_id,
            new_round,
            streak,
            current_riggs_auction_id: riggs_out,
            leader: leader_out,
        },
    )
    .await;

    Ok(Json(json!({
        "top_id": top_id,
        "status": status_str,
        "round": new_round,
        "streak": streak,
        "leader": leader_out,
        "last_price": last_price,
        "new_riggs_auction_id": new_riggs_id,
        "current_riggs_auction_id": riggs_out,
        "force": force
    })))
}

#[derive(Deserialize, Default)]
struct SettleReq {
    pub k: Option<usize>,
}

async fn settle(
    State(s): State<AppState>,
    Path(auction_id): Path<u32>,
    Json(req): Json<SettleReq>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let riggs = resolve_riggs_for_path(&s, auction_id).await;
    let (price, winners) = {
        let mut w = s.world.lock().await;
        let house_pp = w.house_pp.clone();
        let auction_pp = w.auction_pp.clone();
        let k = req.k.unwrap_or(0);
        let (price, winners) = w
            .house
            .complete_kplusone_price_auction(&house_pp, &auction_pp, riggs, k)
            .map_err(|e| (StatusCode::BAD_REQUEST, format!("settle: {e}")))?;
        w.finalize_private_after_settlement(riggs, price, &winners)
            .map_err(|e| (StatusCode::BAD_REQUEST, format!("finalize: {e}")))?;
        (price, winners)
    };
    emit(&s, Event::Settled {
        auction_id: riggs,
        price,
        winners: winners.clone(),
    })
    .await;
    Ok(Json(json!({
        "auction_id": riggs,
        "price": price,
        "winners": winners,
        "ok": true
    })))
}

#[derive(Deserialize)]
struct BruteStartReq {
    pub auction_id: u32,
    pub target_user_id: u32,
}

async fn bruteforce_start(
    State(s): State<AppState>,
    Json(req): Json<BruteStartReq>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let (time_pp, ped_pp, comm, bid_stored, bid_id) = {
        let w = s.world.lock().await;
        w.force_open_prepare(req.auction_id, req.target_user_id)
            .map_err(|e| (StatusCode::NOT_FOUND, e))?
    };
    let task_id = uuid::Uuid::new_v4().to_string();
    let cancel = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let progress = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    let handle = BruteForceHandle {
        cancel: cancel.clone(),
        progress: progress.clone(),
        auction_id: req.auction_id,
        target_user_id: req.target_user_id,
        started: Instant::now(),
    };
    s.bruteforce_tasks
        .lock()
        .await
        .insert(task_id.clone(), handle);

    let s_crack = s.clone();
    let tid_crack = task_id.clone();
    let aid = req.auction_id;
    let uid = req.target_user_id;
    let cancel_bg = cancel.clone();
    let progress_bg = progress.clone();
    tokio::spawn(async move {
        let t0 = Instant::now();
        let res = tokio::task::spawn_blocking(move || {
            // v4.3：brute-force 与老师 force-open 走完全一致的 honest 链路：
            //   真 2^T 顺序平方 + Wesolowski PoE::prove + AES 解密，返回 (bid_revealed, lazy_opening)。
            vsbmas_core::house::rsw_bruteforce_real(
                &comm,
                &time_pp,
                &ped_pp,
                cancel_bg.as_ref(),
                progress_bg.as_ref(),
            )
        })
        .await;
        let elapsed = t0.elapsed().as_millis() as u64;
        if let Ok(Ok((bid_revealed, lazy_opening))) = res {
            emit(
                &s_crack,
                Event::BruteForceCracked {
                    task_id: tid_crack.clone(),
                    auction_id: aid,
                    user_id: uid,
                    bid_revealed,
                    squarings_done: 1u64 << time_param(),
                    elapsed_ms: elapsed,
                },
            )
            .await;

            match try_claim_force_open(&s_crack, aid, uid).await {
                ClaimOutcome::Fresh => {
                    // v4.3：复用老师那条 `force_open_settle` 链路——同一个 account_force_open +
                    // confirm_bid_force_open + revealed_bid_ids 写入，同一个 ForceOpened 事件，
                    // 保证大屏 / 教师端 / 学生端渲染与老师触发时完全一致。
                    let settle_res = {
                        let mut w = s_crack.world.lock().await;
                        w.force_open_settle(
                            aid,
                            uid,
                            bid_id,
                            bid_stored,
                            bid_revealed,
                            lazy_opening.clone(),
                        )
                    };
                    match settle_res {
                        Ok(()) => {
                            {
                                let mut w = s_crack.world.lock().await;
                                w.record_reveal(aid, uid, bid_revealed);
                            }
                            let rankings = {
                                let w = s_crack.world.lock().await;
                                w.bid_rankings_snapshot(aid)
                            };
                            let ov = tc_opening_view_with_meta(
                                &lazy_opening,
                                tc_force_meta(Some(elapsed), Some(true)),
                            );
                            store_force_open_cache(
                                &s_crack,
                                aid,
                                uid,
                                ForceOpenCached {
                                    bid_revealed,
                                    opening: ov.clone(),
                                    rankings: rankings.clone(),
                                    computation_ms: elapsed,
                                    trigger: "bruteforce".into(),
                                },
                            )
                            .await;
                            release_force_open_claim(&s_crack, aid, uid).await;
                            emit(
                                &s_crack,
                                Event::ForceOpened {
                                    auction_id: aid,
                                    user_id: uid,
                                    bid_revealed: Some(bid_revealed),
                                    opening: ov,
                                    rankings: Some(rankings),
                                },
                            )
                            .await;
                            let (t, av, fr) = {
                                let w = s_crack.world.lock().await;
                                w.account_balances(uid)
                            };
                            emit(
                                &s_crack,
                                Event::AccountBalanceSnapshot {
                                    user_id: uid,
                                    total: t,
                                    available: av,
                                    frozen: fr,
                                },
                            )
                            .await;
                        }
                        Err(e) => {
                            release_force_open_claim(&s_crack, aid, uid).await;
                            tracing::warn!(
                                auction_id = aid,
                                user_id = uid,
                                err = %e,
                                "bruteforce settle (force_open_settle) failed"
                            );
                        }
                    }
                }
                ClaimOutcome::AlreadyRevealed(_) => {
                    tracing::info!(
                        auction_id = aid,
                        user_id = uid,
                        "bruteforce settle: already revealed, skip"
                    );
                }
                ClaimOutcome::InFlight => {
                    tracing::info!(
                        auction_id = aid,
                        user_id = uid,
                        "bruteforce settle: teacher force-open already in flight, skip"
                    );
                }
            }
        }
        s_crack.bruteforce_tasks.lock().await.remove(&tid_crack);
    });

    let s_mon = s.clone();
    let tid = task_id.clone();
    let aid = req.auction_id;
    let uid = req.target_user_id;
    let t_eff = time_param();
    let total_steps_u64: u64 = 1u64 << t_eff;
    let total_steps_str = format!("2^{} = {} (sequential squarings)", t_eff, total_steps_u64);
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_millis(700));
        loop {
            interval.tick().await;
            let guard = s_mon.bruteforce_tasks.lock().await;
            let Some(h) = guard.get(&tid) else {
                break;
            };
            let n = h.progress.load(Ordering::Relaxed);
            let elapsed = h.started.elapsed().as_millis() as u64;
            let rate = if elapsed > 0 {
                n as f64 / (elapsed as f64 / 1000.0)
            } else {
                0.0
            };
            let total_f = total_steps_u64 as f64;
            let est = if rate > 0.0 {
                total_f / rate
            } else {
                f64::INFINITY
            };
            drop(guard);
            emit(
                &s_mon,
                Event::BruteForceProgress {
                    task_id: tid.clone(),
                    auction_id: aid,
                    target_user_id: uid,
                    squarings_done: n,
                    total_sequential_steps: total_steps_str.clone(),
                    time_param_t: t_eff,
                    rate_per_sec: rate,
                    estimated_total_secs: est,
                    elapsed_ms: elapsed,
                },
            )
            .await;
        }
    });

    Ok(Json(json!({ "ok": true, "task_id": task_id })))
}

#[derive(Deserialize)]
struct BruteStopReq {
    pub task_id: String,
}

async fn bruteforce_stop(
    State(s): State<AppState>,
    Json(req): Json<BruteStopReq>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let h = s
        .bruteforce_tasks
        .lock()
        .await
        .remove(&req.task_id)
        .ok_or((StatusCode::NOT_FOUND, "unknown task".into()))?;
    h.cancel.store(true, Ordering::Relaxed);
    let n = h.progress.load(Ordering::Relaxed);
    emit(
        &s,
        Event::BruteForceStopped {
            task_id: req.task_id.clone(),
            reason: "stopped-by-user".into(),
            squarings_done: n,
        },
    )
    .await;
    Ok(Json(json!({ "ok": true, "squarings_done": n })))
}

async fn bruteforce_status(
    State(s): State<AppState>,
    Path(task_id): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let g = s.bruteforce_tasks.lock().await;
    let Some(h) = g.get(&task_id) else {
        return Ok(Json(json!({ "ok": false, "msg": "not running" })));
    };
    let n = h.progress.load(Ordering::Relaxed);
    let elapsed = h.started.elapsed().as_millis() as u64;
    Ok(Json(json!({
        "ok": true,
        "task_id": task_id,
        "squarings_done": n,
        "elapsed_ms": elapsed,
        "auction_id": h.auction_id,
        "target_user_id": h.target_user_id,
    })))
}

async fn ws_handler(State(s): State<AppState>, ws: WebSocketUpgrade) -> Response {
    ws.on_upgrade(|sock| ws_loop(sock, s))
}

async fn ws_loop(mut sock: WebSocket, s: AppState) {
    let mut rx = s.events_tx.subscribe();

    if let Ok(content) = tokio::fs::read_to_string(&s.audit.path).await {
        for line in content.lines() {
            if line.is_empty() {
                continue;
            }
            if sock.send(Message::Text(line.to_string())).await.is_err() {
                return;
            }
        }
    }

    loop {
        tokio::select! {
            Ok(msg) = rx.recv() => {
                if sock.send(Message::Text(msg)).await.is_err() { break; }
            }
            recv = sock.recv() => {
                match recv {
                    Some(Ok(Message::Ping(p))) => { let _ = sock.send(Message::Pong(p)).await; }
                    Some(Ok(Message::Close(_))) | None => break,
                    _ => {}
                }
            }
        }
    }
}
