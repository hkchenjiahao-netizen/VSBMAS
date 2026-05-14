//! A1–A6 演示（md 15）
use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde::Deserialize;

use vsbmas_core::events::Event;
use vsbmas_core::serialize::tc_opening_view;

use crate::emit;
use crate::state::AppState;

#[derive(Deserialize)]
pub struct AttackReq {
    pub auction_id: u32,
    pub user_id: u32,
    pub amount: Option<u64>,
    pub fake_bid: Option<u32>,
}

#[axum::debug_handler]
pub async fn a1_oversize(
    State(s): State<AppState>,
    Json(r): Json<AttackReq>,
) -> impl IntoResponse {
    let amount = r.amount.unwrap_or(99_999_999) as u32;
    let mut w = s.world.lock().await;
    let house_pp = w.house_pp.clone();
    let auction_pp = w.auction_pp.clone();
    let private = match w.privates.get(&r.user_id).cloned() {
        Some(p) => p,
        None => return (StatusCode::NOT_FOUND, "unknown user").into_response(),
    };
    let propose_res = private
        .propose_bid(&mut w.rng, &house_pp, &auction_pp, amount)
        .map(|_| ())
        .map_err(|e| e.to_string());
    drop(w);
    match propose_res {
        Ok(()) => (StatusCode::OK, "unexpectedly accepted").into_response(),
        Err(msg) => {
            emit(
                &s,
                Event::VerificationFailed {
                    actor: r.user_id,
                    auction_id: Some(r.auction_id),
                    reason: msg.clone(),
                    category: "A1-oversize".into(),
                },
            )
            .await;
            (StatusCode::BAD_REQUEST, msg).into_response()
        }
    }
}

#[axum::debug_handler]
pub async fn a2_refuse_self_open(
    State(s): State<AppState>,
    Json(r): Json<AttackReq>,
) -> impl IntoResponse {
    emit(
        &s,
        Event::VerificationFailed {
            actor: r.user_id,
            auction_id: Some(r.auction_id),
            reason: "user refuses to self-open; force-open reward will apply".into(),
            category: "A2-refuse-open".into(),
        },
    )
    .await;

    // VF 之后自动尝试强揭；若当前尚未投标/阶段未到，则静默返回。
    let force_result = {
        let mut w = s.world.lock().await;
        w.apply_force_open_cheating(r.auction_id, r.user_id)
    };
    match force_result {
        Ok((bid_revealed, opening)) => {
            let opening_view = tc_opening_view(&opening);
            emit(
                &s,
                Event::ForceOpened {
                    auction_id: r.auction_id,
                    user_id: r.user_id,
                    bid_revealed: Some(bid_revealed),
                    opening: opening_view.clone(),
                    rankings: None,
                },
            )
            .await;
            Json(serde_json::json!({
                "ok": true,
                "msg": "force-opened",
                "bid_revealed": bid_revealed,
                "opening": opening_view,
            }))
            .into_response()
        }
        Err(e) => {
            tracing::info!(user = r.user_id, auction = r.auction_id, err = %e, "A2 force_open skipped");
            Json(serde_json::json!({ "ok": true, "msg": "will be force-opened", "note": e }))
                .into_response()
        }
    }
}

#[axum::debug_handler]
pub async fn a3_tampered_proof(
    State(s): State<AppState>,
    Json(r): Json<AttackReq>,
) -> impl IntoResponse {
    let aid = r.auction_id;
    let uid = r.user_id;
    let amount = r.amount.unwrap_or(100) as u32;

    let res = {
        let mut w = s.world.lock().await;
        w.tampered_account_bid(aid, uid, amount)
    };

    match res {
        Ok(_) => (StatusCode::OK, "unexpectedly accepted").into_response(),
        Err(msg) => {
            emit(
                &s,
                Event::VerificationFailed {
                    actor: uid,
                    auction_id: Some(aid),
                    reason: format!("tampered range proof rejected: {msg}"),
                    category: "A3-tampered-proof".into(),
                },
            )
            .await;
            (StatusCode::BAD_REQUEST, msg).into_response()
        }
    }
}

#[axum::debug_handler]
pub async fn a4_replay(
    State(s): State<AppState>,
    Json(r): Json<AttackReq>,
) -> impl IntoResponse {
    let aid = r.auction_id;
    let amt = r.amount.unwrap_or(10) as u32;

    enum Step {
        UnknownUser,
        ProposeFailed(String),
        SetupFailed(String),
        ReplayAccepted,
        ReplayRejected(String),
    }

    let step = {
        let mut w = s.world.lock().await;
        let house_pp = w.house_pp.clone();
        let auction_pp = w.auction_pp.clone();
        match w.privates.get(&r.user_id).cloned() {
            None => Step::UnknownUser,
            Some(private) => match private.propose_bid(&mut w.rng, &house_pp, &auction_pp, amt) {
                Err(e) => Step::ProposeFailed(e.to_string()),
                Ok((bp, op)) => {
                    let new_bid_id = *w.bids_per_riggs_auction.get(&aid).unwrap_or(&0);
                    if let Err(e) =
                        w.house.account_bid(&house_pp, &auction_pp, aid, r.user_id, &bp)
                    {
                        Step::SetupFailed(e.to_string())
                    } else {
                        if let Some(p) = w.privates.get_mut(&r.user_id) {
                            let _ = p.confirm_bid(&house_pp, &auction_pp, aid, amt, &bp, &op);
                        }
                        *w.bids_per_riggs_auction.entry(aid).or_insert(0) += 1;
                        w.bid_index.insert((aid, r.user_id), new_bid_id);
                        match w.house.account_bid(&house_pp, &auction_pp, aid, r.user_id, &bp) {
                            Ok(_) => Step::ReplayAccepted,
                            Err(e) => Step::ReplayRejected(e.to_string()),
                        }
                    }
                }
            },
        }
    };

    match step {
        Step::UnknownUser => (StatusCode::NOT_FOUND, "unknown user").into_response(),
        Step::ProposeFailed(msg) => (StatusCode::BAD_REQUEST, msg).into_response(),
        Step::SetupFailed(msg) => {
            emit(
                &s,
                Event::VerificationFailed {
                    actor: r.user_id,
                    auction_id: Some(aid),
                    reason: format!("replay setup failed: {msg}"),
                    category: "A4-replay".into(),
                },
            )
            .await;
            (StatusCode::BAD_REQUEST, msg).into_response()
        }
        Step::ReplayAccepted => (StatusCode::OK, "unexpectedly accepted").into_response(),
        Step::ReplayRejected(msg) => {
            emit(
                &s,
                Event::VerificationFailed {
                    actor: r.user_id,
                    auction_id: Some(aid),
                    reason: format!("replay rejected: {msg}"),
                    category: "A4-replay".into(),
                },
            )
            .await;
            (StatusCode::BAD_REQUEST, msg).into_response()
        }
    }
}

#[axum::debug_handler]
pub async fn a5_fake_self_open(
    State(s): State<AppState>,
    Json(r): Json<AttackReq>,
) -> impl IntoResponse {
    let aid = r.auction_id;
    let fake_bid = r.fake_bid.unwrap_or(999);

    enum Step {
        UnknownUser,
        NoActiveBid,
        FakeAccepted,
        FakeRejected(String),
    }

    let step = {
        let mut w = s.world.lock().await;
        // HTTP self_open is teacher-phase gated; A5 must still hit `account_self_open` in md15.
        w.set_teacher_phase(aid, "BidSelfOpening");
        let house_pp = w.house_pp.clone();
        let auction_pp = w.auction_pp.clone();
        match w.privates.get(&r.user_id).cloned() {
            None => Step::UnknownUser,
            Some(p) => match p.active_bids.get(&aid).cloned() {
                None => Step::NoActiveBid,
                Some((_real_bid, opening, _)) => {
                    let res = w.house.account_self_open(
                        &house_pp,
                        &auction_pp,
                        aid,
                        r.user_id,
                        fake_bid,
                        &opening,
                    );
                    match res {
                        Ok(_) => Step::FakeAccepted,
                        Err(e) => Step::FakeRejected(e.to_string()),
                    }
                }
            },
        }
    };

    match step {
        Step::UnknownUser => {
            emit(
                &s,
                Event::VerificationFailed {
                    actor: r.user_id,
                    auction_id: Some(aid),
                    reason: "unknown user".into(),
                    category: "A5-fake-opening".into(),
                },
            )
            .await;
            (StatusCode::NOT_FOUND, "unknown").into_response()
        }
        Step::NoActiveBid => {
            emit(
                &s,
                Event::VerificationFailed {
                    actor: r.user_id,
                    auction_id: Some(aid),
                    reason: "no active bid".into(),
                    category: "A5-fake-opening".into(),
                },
            )
            .await;
            (StatusCode::BAD_REQUEST, "no active bid").into_response()
        }
        Step::FakeAccepted => (StatusCode::OK, "unexpectedly accepted").into_response(),
        Step::FakeRejected(msg) => {
            emit(
                &s,
                Event::VerificationFailed {
                    actor: r.user_id,
                    auction_id: Some(aid),
                    reason: format!("fake opening rejected: {msg}"),
                    category: "A5-fake-opening".into(),
                },
            )
            .await;
            (StatusCode::BAD_REQUEST, msg).into_response()
        }
    }
}

#[axum::debug_handler]
pub async fn a6_peek_ciphertext(
    State(s): State<AppState>,
    Json(r): Json<AttackReq>,
) -> impl IntoResponse {
    emit(
        &s,
        Event::VerificationFailed {
            actor: r.user_id,
            auction_id: Some(r.auction_id),
            reason: "By design: only hex previews; plaintext never served (A6 demo)".into(),
            category: "A6-peek".into(),
        },
    )
    .await;
    Json(serde_json::json!({
        "ok": true,
        "auction_id": r.auction_id,
        "note": "By design: this endpoint returns only hex previews. Plaintext is never served.",
        "commitments_hex_preview": []
    }))
}
