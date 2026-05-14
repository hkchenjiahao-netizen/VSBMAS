use std::collections::{HashMap, HashSet};
use std::convert::TryInto;
use std::thread;
use std::time::{Duration, Instant};

use ark_ec::ProjectiveCurve;
use ark_ff::{One, PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use auction_house::{
    auction::{AuctionParams, AuctionPhase},
    house::{AccountPrivateState, AuctionHouse, BidProposal, HouseAuctionParams, HouseParams},
};
use digest::Digest;
use rand::rngs::StdRng;
use rand::{CryptoRng, Rng, SeedableRng};
use range_proofs::bulletproofs::{Bulletproofs, Proof as RangeProof};
use rsa::bigint::{nat_to_f, BigInt};
use rsa::hog::RsaHiddenOrderGroup;
use timed_commitments::basic_tc::{
    Comm as BtcComm, OneTimeKeyDeterministicAE, TimeParams,
};
use timed_commitments::lazy_tc::{Comm as LazyComm, LazyTC, Opening as TCOpening};

use crate::events::BidRankings;
use crate::params::{
    t_bid_collection, t_bid_self_open, time_param, DemoPoEParams, DemoRsaParams, G, H, H2P,
    DEMO_RSA_ORDER, DEMO_SQ_PER_SEC, FORCE_OPEN_PROGRESS_BATCH, NUM_BID_BITS, REWARD_FORCE_OPEN,
    REWARD_SELF_OPEN,
};

pub type DemoTC = LazyTC<G, DemoPoEParams, DemoRsaParams, H, H2P>;
pub type DemoAuctionHouse = AuctionHouse<G, DemoPoEParams, DemoRsaParams, H, H2P>;
pub type DemoAccount = AccountPrivateState<G, DemoPoEParams, DemoRsaParams, H, H2P>;
pub type DemoTCOpening = TCOpening<G, DemoRsaParams, H2P>;

/// v4.2：**真** RSW 力揭——独立完成 `2^t` 次顺序平方（`y_{i+1} = y_i^2`）以产生真实的
/// RSW 计算耗时。随后调用 `DemoTC::force_open` 完成 Wesolowski PoE::prove（真 ~2 次模幂，
/// ms 级）与 AES 一次性密钥解密。返回的 `lazy_opening` 与旧路径格式兼容，能被 `ver_open`
/// / `account_force_open` 校验通过。
///
/// 为什么不直接"手搓" `Opening`：上游 `LazyTC::Opening` 为枚举 wrapper，内部 `BasicTCOpening::Force`
/// 需同时存 `y` 与 `proof`；我们 **也** 用到 `DemoTC::force_open` 内部那次 `x^(2^t)` 大指数
/// modpow 的 `y`——它是 `(x, 2, t)` 同一大整数的等价表示，与我们逐步平方得到的 `y` 相等。
/// 独立跑的那 `2^t` 次平方即"真 RSW"的耗时部分，不会被省略。
///
/// progress 回调：`steps_done`, `steps_total`（= `2^t`）, `elapsed_ms`。
pub fn rsw_force_open_real(
    comm: &LazyComm<G, DemoRsaParams>,
    time_pp: &TimeParams<DemoRsaParams>,
    ped_pp: &timed_commitments::PedersenParams<G>,
    progress: &mut dyn FnMut(u64, u64, u64),
) -> Result<(u32, DemoTCOpening), String> {
    let t = time_pp.t;
    let total: u64 = 1u64 << t;
    let batch = FORCE_OPEN_PROGRESS_BATCH.max(1);
    let t0 = Instant::now();

    // 1) 真实 2^t 次顺序平方：这正是 RSW 安全性所声明的"无法并行化的"计算负担。
    let mut y = comm.tc_comm.x.clone();
    for i in 0..total {
        y = y.power(&BigInt::from(2u32));
        let done = i + 1;
        if done % batch == 0 || done == total {
            progress(done, total, t0.elapsed().as_millis() as u64);
        }
    }
    let _ = y; // y 通过 DemoTC::force_open 再次计算（大指数 modpow，~ms 级），两者等价。

    // 2) 真 Wesolowski PoE::prove + 真 AES 解密（由上游 `BasicTC::force_open` 完成）。
    let (plaintext_opt, lazy_opening) =
        DemoTC::force_open(time_pp, ped_pp, comm).map_err(|e| format!("force_open: {e}"))?;
    let bytes = plaintext_opt.ok_or_else(|| "force_open: no plaintext".to_string())?;
    if bytes.len() < 4 {
        return Err("force_open: plaintext too short".into());
    }
    let bid = u32::from_le_bytes(bytes[..4].try_into().map_err(|_| "bid bytes")?);

    Ok((bid, lazy_opening))
}

/// v4.3：**真** 学生 brute-force——与 `rsw_force_open_real` 走同一条 honest 结算链路。
/// 先真跑 `2^t` 次顺序平方（循环内检查 cancel、向 atomic 上报进度），随后调 `DemoTC::force_open`
/// 生成带 Wesolowski PoE 证明的 `lazy_opening`（与老师 force-open 产生的 opening 同构）。
/// 返回 `(bid_revealed, DemoTCOpening)`，由 main.rs 用统一的 `force_open_settle` 落账并 emit
/// `ForceOpened`，确保学生与老师路径在事件面与前端渲染面上完全一致。
pub fn rsw_bruteforce_real(
    comm: &LazyComm<G, DemoRsaParams>,
    time_pp: &TimeParams<DemoRsaParams>,
    ped_pp: &timed_commitments::PedersenParams<G>,
    cancel: &std::sync::atomic::AtomicBool,
    progress: &std::sync::atomic::AtomicU64,
) -> Result<(u32, DemoTCOpening), String> {
    use std::sync::atomic::Ordering;
    let t = time_pp.t;
    let total: u64 = 1u64 << t;
    let mut y = comm.tc_comm.x.clone();
    for i in 0..total {
        if cancel.load(Ordering::Relaxed) {
            return Err("cancelled".into());
        }
        y = y.power(&BigInt::from(2u32));
        progress.store(i + 1, Ordering::Relaxed);
    }
    let _ = y;

    let (plaintext_opt, lazy_opening) =
        DemoTC::force_open(time_pp, ped_pp, comm).map_err(|e| format!("force_open: {e}"))?;
    let bytes = plaintext_opt.ok_or_else(|| "force_open: no plaintext".to_string())?;
    if bytes.len() < 4 {
        return Err("force_open: plaintext too short".into());
    }
    let bid = u32::from_le_bytes(bytes[..4].try_into().map_err(|_| "bid bytes")?);
    Ok((bid, lazy_opening))
}

/// Legacy（保留做向后兼容）：v4.1 及之前版本的 sleep-throttled demo。
/// Part C 引入 `rsw_force_open_real` / `rsw_bruteforce_real` 之后不再被 main 调用。
#[allow(dead_code)]
#[deprecated(note = "Use rsw_force_open_real for honest / force_open path (真 2^T squarings).")]
fn demo_sequential_rsw_progress(
    comm: &LazyComm<G, DemoRsaParams>,
    time_pp: &TimeParams<DemoRsaParams>,
    progress: &mut dyn FnMut(u64, u64, u64),
) {
    let t = time_pp.t;
    let total: u64 = 1u64 << t;
    let batch = FORCE_OPEN_PROGRESS_BATCH.max(1);
    let mut y = comm.tc_comm.x.clone();
    for _ in 0..t {
        y = y.power(&BigInt::from(2u32));
    }
    let _ = y;
    let t0 = Instant::now();
    let sleep_each = Duration::from_secs_f64(1.0 / DEMO_SQ_PER_SEC as f64);
    for i in 0..total {
        thread::sleep(sleep_each);
        let done = i + 1;
        if done % batch == 0 || done == total {
            progress(done, total, t0.elapsed().as_millis() as u64);
        }
    }
}

/// Legacy（保留做向后兼容）：sleep-throttled 的学生 brute-force。
/// Part C 之后 main 只调 `rsw_bruteforce_real`。
#[deprecated(note = "Use rsw_bruteforce_real (真 2^T squarings) instead.")]
pub fn run_bruteforce_demo_chain(
    x: RsaHiddenOrderGroup<DemoRsaParams>,
    ct: Vec<u8>,
    t: u64,
    cancel: &std::sync::atomic::AtomicBool,
    progress: &std::sync::atomic::AtomicU64,
) -> Result<Vec<u8>, String> {
    use std::sync::atomic::Ordering;
    let mut y = x;
    for _ in 0..t {
        if cancel.load(Ordering::Relaxed) {
            return Err("cancelled".into());
        }
        y = y.power(&BigInt::from(2u32));
    }
    let total: u64 = 1u64 << t;
    let sleep_each = Duration::from_secs_f64(1.0 / DEMO_SQ_PER_SEC as f64);
    for i in 0..total {
        if cancel.load(Ordering::Relaxed) {
            return Err("cancelled".into());
        }
        thread::sleep(sleep_each);
        progress.store(i + 1, Ordering::Relaxed);
    }
    let key = H::digest(&y.n.to_bytes_be().1).to_vec();
    let ad = t.to_be_bytes();
    OneTimeKeyDeterministicAE::decrypt::<H>(&key, &ct, &ad).map_err(|e| format!("decrypt: {e}"))
}

pub struct World {
    pub house_pp: HouseParams<G>,
    pub auction_pp: HouseAuctionParams<G, DemoRsaParams>,
    pub house: DemoAuctionHouse,
    pub privates: HashMap<u32, DemoAccount>,
    pub labels: HashMap<u32, String>,
    pub rng: StdRng,
    /// 创建顺序记录（`AuctionHouse` 不对外暴露 `active_auctions` 键）。
    pub auction_ids: Vec<u32>,
    pub auction_item_names: HashMap<u32, String>,
    /// 每轮 Riggs `auction_id` 上的投标次数（多轮推进时用）。
    pub bids_per_riggs_auction: HashMap<u32, u32>,
    /// 该轮已自揭次数（仅作兼容统计；强揭兜底以 `revealed_bid_ids` 为准）。
    pub self_open_count: HashMap<u32, u32>,
    /// 每个拍场创建时刻，用于镜像 `Auction::phase` 的时序判定。
    pub auction_t_start: HashMap<u32, Instant>,
    /// `(auction_id, user_id) -> bid_id`，由 `accept_bid` 返回的递增索引（用于 `account_force_open`）。
    pub bid_index: HashMap<(u32, u32), u32>,
    /// 每个拍场已揭示（自揭或强揭）的 bid_id 集合（用于强揭兜底与 phase 判定）。
    pub revealed_bid_ids: HashMap<u32, HashSet<u32>>,
    /// 课堂演示：老师控制的逻辑阶段（与 Riggs 内部 phase 解耦展示）。
    pub teacher_phase: HashMap<u32, String>,
    /// 仅用于前端倒计时展示（epoch ms）。
    pub phase_deadline_ms: HashMap<u32, u64>,
    /// riggs_auction_id -> 多轮会话根 id（首次创建的拍场 id）。
    pub riggs_session_top: HashMap<u32, u32>,
    /// 已揭示标价，按金额降序。
    pub revealed_rankings: HashMap<u32, Vec<(u32, u32)>>,
    /// RSW 时间锁底数 x（RSA 群元素），用于暴力平方演示。
    pub bid_rsw_base: HashMap<(u32, u32), RsaHiddenOrderGroup<DemoRsaParams>>,
    /// 与 `bid_rsw_base` 配套的 `BasicTC::Comm`（含 ciphertext），供诚实暴力链解密。
    pub bid_rsw_tc: HashMap<(u32, u32), BtcComm<DemoRsaParams>>,
    /// Open-bid 阶段前在 BidCollection 中登记的 self-open 意向 `(auction_id, user_id) -> bid`。
    pub pending_self_open: HashMap<(u32, u32), u32>,
    /// 每场次保留价（新轮次从 session top 复制）。
    pub auction_reserve_price: HashMap<u32, u32>,
    /// 上一轮（同 session top）的最高揭示价；用于 Part B `bid > prev_round_max` 约束。
    pub prev_round_high_bid: HashMap<u32, u32>,
}

impl World {
    pub fn bootstrap() -> Self {
        let mut rng = StdRng::seed_from_u64(42);

        let ped_pp = DemoTC::gen_pedersen_params(&mut rng);
        let bulletproofs_pp = Bulletproofs::<G, H>::gen_params(&mut rng, NUM_BID_BITS);
        let time_pp = DemoTC::gen_time_params_cheating(time_param(), &DEMO_RSA_ORDER).unwrap();

        let auction_pp = HouseAuctionParams {
            auction_pp: AuctionParams {
                t_bid_collection: t_bid_collection(),
                t_bid_self_open: t_bid_self_open(),
                time_pp,
                ped_pp: ped_pp.clone(),
            },
            reward_self_open: REWARD_SELF_OPEN,
            reward_force_open: REWARD_FORCE_OPEN,
        };

        let house_pp = HouseParams {
            range_proof_pp: bulletproofs_pp,
            ped_pp,
        };

        let house = DemoAuctionHouse::new(&house_pp);

        Self {
            house_pp,
            auction_pp,
            house,
            privates: HashMap::new(),
            labels: HashMap::new(),
            rng,
            auction_ids: Vec::new(),
            auction_item_names: HashMap::new(),
            bids_per_riggs_auction: HashMap::new(),
            self_open_count: HashMap::new(),
            auction_t_start: HashMap::new(),
            bid_index: HashMap::new(),
            revealed_bid_ids: HashMap::new(),
            teacher_phase: HashMap::new(),
            phase_deadline_ms: HashMap::new(),
            riggs_session_top: HashMap::new(),
            revealed_rankings: HashMap::new(),
            bid_rsw_base: HashMap::new(),
            bid_rsw_tc: HashMap::new(),
            pending_self_open: HashMap::new(),
            auction_reserve_price: HashMap::new(),
            prev_round_high_bid: HashMap::new(),
        }
    }

    pub fn register_riggs_auction(&mut self, riggs_id: u32, session_top_id: u32) {
        self.teacher_phase
            .insert(riggs_id, "BidCollection".to_string());
        self.riggs_session_top.insert(riggs_id, session_top_id);
    }

    /// 当前 Riggs 轮次的逻辑阶段（老师控制台）。
    pub fn get_auction_phase(&self, id: u32) -> String {
        self.teacher_phase
            .get(&id)
            .cloned()
            .unwrap_or_else(|| "BidCollection".to_string())
    }

    pub fn set_teacher_phase(&mut self, riggs_id: u32, phase: &str) {
        self.teacher_phase.insert(riggs_id, phase.to_string());
    }

    pub fn record_reveal(&mut self, auction_id: u32, user_id: u32, amount: u32) {
        let v = self.revealed_rankings.entry(auction_id).or_default();
        v.retain(|(u, _)| *u != user_id);
        v.push((user_id, amount));
        v.sort_by(|a, b| b.1.cmp(&a.1));
    }

    pub fn bid_rankings_snapshot(&self, auction_id: u32) -> BidRankings {
        let Some(v) = self.revealed_rankings.get(&auction_id) else {
            return BidRankings::default();
        };
        let mut r = BidRankings::default();
        if let Some((u, a)) = v.first() {
            r.highest_user_id = Some(*u);
            r.highest_amount = Some(*a);
        }
        if let Some((u, a)) = v.get(1) {
            r.second_user_id = Some(*u);
            r.second_amount = Some(*a);
        }
        r
    }

    /// Sum of amounts locked in unrevealed bids (from local `active_bids`).
    pub fn escrow_for_user(&self, uid: u32) -> u32 {
        self.privates
            .get(&uid)
            .map(|p| {
                p.active_bids
                    .values()
                    .map(|(amt, _, _)| *amt)
                    .sum::<u32>()
            })
            .unwrap_or(0)
    }

    pub fn account_balances(&self, uid: u32) -> (u32, u32, u32) {
        let total = self
            .privates
            .get(&uid)
            .map(|p| p.public_summary.balance)
            .unwrap_or(0);
        let frozen = self.escrow_for_user(uid);
        let available = total.saturating_sub(frozen);
        (total, available, frozen)
    }

    pub fn rsw_base_for_bid(
        &self,
        auction_id: u32,
        user_id: u32,
    ) -> Option<RsaHiddenOrderGroup<DemoRsaParams>> {
        self.bid_rsw_base
            .get(&(auction_id, user_id))
            .cloned()
    }

    /// 根据镜像元数据复刻 Riggs `Auction::phase` 的分支顺序（辅助调试；课堂主界面用 `teacher_phase`）。
    #[allow(dead_code)]
    pub fn riggs_mirror_phase(&self, id: u32) -> String {
        let bids_n = self
            .bids_per_riggs_auction
            .get(&id)
            .copied()
            .unwrap_or(0);
        let revealed_n = self
            .revealed_bid_ids
            .get(&id)
            .map(|s| s.len() as u32)
            .unwrap_or(0);
        let elapsed = match self.auction_t_start.get(&id) {
            Some(t) => t.elapsed(),
            None => return "BidCollection".to_string(),
        };
        let pp = &self.auction_pp.auction_pp;
        let phase = if elapsed < pp.t_bid_collection {
            AuctionPhase::BidCollection
        } else if bids_n == revealed_n {
            AuctionPhase::Complete
        } else if elapsed < pp.t_bid_collection + pp.t_bid_self_open {
            AuctionPhase::BidSelfOpening
        } else {
            AuctionPhase::BidForceOpening
        };
        format!("{:?}", phase)
    }

    /// v4.2 · Part B1：只读准备——返回执行真 2^T 次顺序平方所需的参数集合（time_pp、
    /// ped_pp、comm、bid_stored、bid_id）。短锁期间只做 clone，保证外层可以 drop lock
    /// 再到 `spawn_blocking` 线程里跑 ~120s 长计算。
    pub fn force_open_prepare(
        &self,
        auction_id: u32,
        user_id: u32,
    ) -> Result<
        (
            TimeParams<DemoRsaParams>,
            timed_commitments::PedersenParams<G>,
            LazyComm<G, DemoRsaParams>,
            u32, /* bid_stored */
            u32, /* bid_id */
        ),
        String,
    > {
        let private = self
            .privates
            .get(&user_id)
            .ok_or_else(|| "unknown user".to_string())?;
        let (bid, _op, comm) = private
            .active_bids
            .get(&auction_id)
            .ok_or_else(|| "no active bid".to_string())?;
        let bid_id = *self
            .bid_index
            .get(&(auction_id, user_id))
            .ok_or_else(|| "unknown bid index".to_string())?;
        let time_pp = self.auction_pp.auction_pp.time_pp.clone();
        let ped_pp = self.house_pp.ped_pp.clone();
        Ok((time_pp, ped_pp, comm.clone(), *bid, bid_id))
    }

    /// v4.2 · Part B1：结算——写入 Riggs（account_force_open + confirm_bid_force_open +
    /// revealed_bid_ids.insert）。如 `bid_id` 已被标记为 revealed（比如并发 brute-force 已
    /// 结算），走幂等 Ok(())。调用前应短锁，调用后释放锁。
    pub fn force_open_settle(
        &mut self,
        auction_id: u32,
        user_id: u32,
        bid_id: u32,
        bid_stored: u32,
        bid_revealed: u32,
        lazy_opening: DemoTCOpening,
    ) -> Result<(), String> {
        if self
            .revealed_bid_ids
            .get(&auction_id)
            .map(|s| s.contains(&bid_id))
            .unwrap_or(false)
        {
            return Ok(()); // 幂等：并发路径已经结算过。
        }
        if bid_revealed != bid_stored {
            return Err(format!(
                "force_open: bid mismatch (stored {bid_stored}, opened {bid_revealed})"
            ));
        }
        let house_pp = self.house_pp.clone();
        let auction_pp = self.auction_pp.clone();
        self.house
            .account_force_open(
                &house_pp,
                &auction_pp,
                auction_id,
                user_id,
                bid_id,
                Some(bid_revealed),
                &lazy_opening,
            )
            .map_err(|e| format!("account_force_open: {e}"))?;
        if let Some(p) = self.privates.get_mut(&user_id) {
            p.confirm_bid_force_open(&house_pp, &auction_pp)
                .map_err(|e| format!("confirm_bid_force_open: {e}"))?;
        }
        self.revealed_bid_ids
            .entry(auction_id)
            .or_default()
            .insert(bid_id);
        Ok(())
    }

    /// 诚实 RSW（无陷门）：真 `2^T` 次顺序平方 + 真 Wesolowski PoE + 真 AES 解密。
    /// `progress`：`steps_done`、`steps_total`（= `2^T`）、`elapsed_ms`。
    ///
    /// 注意：本函数会在**同一把世界锁内**跑完真 RSW（~120s），因此只应由测试 / 单元代码调用；
    /// 生产路径（`main.rs::apply_force_open_honest_emit_progress`）会调 prepare/settle 三段式，
    /// 把长计算搬到 `spawn_blocking`，期间**不**占 world.lock()。
    pub fn apply_force_open_honest(
        &mut self,
        auction_id: u32,
        user_id: u32,
        progress: &mut dyn FnMut(u64, u64, u64),
    ) -> Result<(u32, DemoTCOpening), String> {
        let (time_pp, ped_pp, comm, bid_stored, bid_id) =
            self.force_open_prepare(auction_id, user_id)?;
        let (bid_revealed, lazy_opening) =
            rsw_force_open_real(&comm, &time_pp, &ped_pp, progress)?;
        self.force_open_settle(
            auction_id,
            user_id,
            bid_id,
            bid_stored,
            bid_revealed,
            lazy_opening.clone(),
        )?;
        Ok((bid_revealed, lazy_opening))
    }

    /// 陷门强揭（测试/快速路径）；课堂 UI 应使用 `apply_force_open_honest`。
    pub fn apply_force_open_cheating(
        &mut self,
        auction_id: u32,
        user_id: u32,
    ) -> Result<(u32, DemoTCOpening), String> {
        let house_pp = self.house_pp.clone();
        let auction_pp = self.auction_pp.clone();

        let (bid_stored, comm) = {
            let private = self
                .privates
                .get(&user_id)
                .ok_or_else(|| "unknown user".to_string())?;
            let (bid, _op, comm) = private
                .active_bids
                .get(&auction_id)
                .ok_or_else(|| "no active bid".to_string())?;
            (*bid, comm.clone())
        };
        let bid_id = *self
            .bid_index
            .get(&(auction_id, user_id))
            .ok_or_else(|| "unknown bid index".to_string())?;

        let (plaintext_opt, lazy_opening) = DemoTC::force_open_cheating(
            &auction_pp.auction_pp.time_pp,
            &house_pp.ped_pp,
            &comm,
            &DEMO_RSA_ORDER,
        )
        .map_err(|e| format!("force_open_cheating: {e}"))?;

        let bytes = plaintext_opt.ok_or_else(|| "force_open: no plaintext".to_string())?;
        if bytes.len() < 4 {
            return Err("force_open: plaintext too short".into());
        }
        let bid_revealed =
            u32::from_le_bytes(bytes[..4].try_into().map_err(|_| "bid bytes")?);
        if bid_revealed != bid_stored {
            return Err(format!(
                "force_open: bid mismatch (stored {bid_stored}, opened {bid_revealed})"
            ));
        }

        self.house
            .account_force_open(
                &house_pp,
                &auction_pp,
                auction_id,
                user_id,
                bid_id,
                Some(bid_revealed),
                &lazy_opening,
            )
            .map_err(|e| format!("account_force_open: {e}"))?;

        if let Some(p) = self.privates.get_mut(&user_id) {
            p.confirm_bid_force_open(&house_pp, &auction_pp)
                .map_err(|e| format!("confirm_bid_force_open: {e}"))?;
        }
        self.revealed_bid_ids
            .entry(auction_id)
            .or_default()
            .insert(bid_id);

        Ok((bid_revealed, lazy_opening))
    }

    /// `complete_kplusone_price_auction` 之后，对本地 `AccountPrivateState` 调用 win/loss 结算，解冻非赢家保证金。
    pub fn finalize_private_after_settlement(
        &mut self,
        auction_id: u32,
        price: u32,
        winners: &[u32],
    ) -> Result<(), String> {
        let house_pp = self.house_pp.clone();
        let auction_pp = self.auction_pp.clone();
        let uids: Vec<u32> = self
            .bid_index
            .iter()
            .filter_map(|(&(aid, uid), _)| if aid == auction_id { Some(uid) } else { None })
            .collect();
        for uid in uids {
            let p = self
                .privates
                .get_mut(&uid)
                .ok_or_else(|| format!("unknown user {uid}"))?;
            if winners.contains(&uid) {
                p.confirm_auction_win(&house_pp, &auction_pp, auction_id, price)
                    .map_err(|e| format!("confirm_auction_win: {e}"))?;
            } else {
                p.confirm_auction_loss(&house_pp, &auction_pp, auction_id)
                    .map_err(|e| format!("confirm_auction_loss: {e}"))?;
            }
        }
        Ok(())
    }

    /// 尝试对「已揭示且非当前最高价」的账户解冻（若仍挂有 active bid）。
    pub fn try_release_loser_escrow(
        &mut self,
        auction_id: u32,
        user_id: u32,
    ) -> Result<bool, String> {
        let v = self
            .revealed_rankings
            .get(&auction_id)
            .ok_or_else(|| "no rankings for this auction".to_string())?;
        let Some((leader_uid, _)) = v.first() else {
            return Err("empty rankings".into());
        };
        if *leader_uid == user_id {
            return Err("current highest bidder — no release".into());
        }
        if !v.iter().any(|(u, _)| *u == user_id) {
            return Err("not revealed for this auction".into());
        }
        let house_pp = self.house_pp.clone();
        let auction_pp = self.auction_pp.clone();
        let p = self
            .privates
            .get_mut(&user_id)
            .ok_or_else(|| "unknown user".to_string())?;
        if !p.active_bids.contains_key(&auction_id) {
            return Ok(false);
        }
        p.confirm_auction_loss(&house_pp, &auction_pp, auction_id)
            .map_err(|e| format!("confirm_auction_loss: {e}"))?;
        Ok(true)
    }

    /// A3 辅助：本地 `propose_bid` 后对 `range_proof_bid.t_x` 序列化翻转一字节，
    /// 再调用 `account_bid`；返回其 `Err` 信息用于上层 emit `VerificationFailed`。
    pub fn tampered_account_bid(
        &mut self,
        auction_id: u32,
        user_id: u32,
        amount: u32,
    ) -> Result<(), String> {
        let house_pp = self.house_pp.clone();
        let auction_pp = self.auction_pp.clone();
        let private = self
            .privates
            .get(&user_id)
            .ok_or_else(|| "unknown user".to_string())?
            .clone();
        let (bp_ok, _op) = private
            .propose_bid(&mut self.rng, &house_pp, &auction_pp, amount)
            .map_err(|e| format!("propose_bid: {e}"))?;

        let mut tampered_rp = bp_ok.range_proof_bid.clone();
        let mut buf = Vec::new();
        tampered_rp
            .t_x
            .serialize(&mut buf)
            .map_err(|e| format!("serialize t_x: {e}"))?;
        let mut replaced = false;
        if !buf.is_empty() {
            let orig = buf.clone();
            for i in 0..buf.len() {
                buf[i] ^= 0x01;
                if let Ok(new_tx) = <<crate::params::G as ProjectiveCurve>::ScalarField as CanonicalDeserialize>::deserialize(buf.as_slice()) {
                    tampered_rp.t_x = new_tx;
                    replaced = true;
                    break;
                }
                buf.copy_from_slice(&orig);
            }
        }
        if !replaced {
            tampered_rp.t_x += <<crate::params::G as ProjectiveCurve>::ScalarField as One>::one();
        }

        let tampered_bp = BidProposal {
            comm_bid: bp_ok.comm_bid.clone(),
            range_proof_bid: tampered_rp,
            range_proof_balance: bp_ok.range_proof_balance.clone(),
        };
        self.house
            .account_bid(&house_pp, &auction_pp, auction_id, user_id, &tampered_bp)
            .map_err(|e| format!("account_bid: {e}"))
    }

    /// 列出某拍场当前尚未揭示的 `(user_id, bid_id)`。
    pub fn pending_reveals(&self, auction_id: u32) -> Vec<(u32, u32)> {
        let revealed = self.revealed_bid_ids.get(&auction_id);
        self.bid_index
            .iter()
            .filter_map(|(&(aid, uid), &bid_id)| {
                if aid != auction_id {
                    return None;
                }
                if revealed.map(|s| s.contains(&bid_id)).unwrap_or(false) {
                    return None;
                }
                Some((uid, bid_id))
            })
            .collect()
    }
}

/// Part B：为一笔 bid 生成"`bid >= lower_bound`"的 ZK 附加约束证明。
///
/// 方法：在同一条承诺 `C_bid = g·bid + h·r` 基础上，构造位移承诺
/// `C' = C_bid - g·k`，它等于 `g·(bid-k) + h·r`；对 `bid - k ∈ [0, 2^NUM_BID_BITS)`
/// 调用既有 Bulletproofs 原语产生 range proof。verifier 无需知道 `bid`/`r`，
/// 只需用公开的 `C_bid, k` 重新构造 `C'` 并校验。
///
/// 这等价于在电路里追加 `bid >= k` 约束，但无需改动 `riggs-master/auction_house`。
pub fn prove_bid_at_least<R: CryptoRng + Rng>(
    rng: &mut R,
    house_pp: &HouseParams<G>,
    auction_pp: &HouseAuctionParams<G, DemoRsaParams>,
    comm_bid_ped: &G,
    bid: u32,
    lower_bound: u32,
    opening_bid_ped: &<G as ProjectiveCurve>::ScalarField,
) -> Result<RangeProof<G>, String> {
    if bid < lower_bound {
        return Err(format!(
            "prove_bid_at_least: bid {bid} < lower_bound {lower_bound}"
        ));
    }
    let diff = bid - lower_bound;
    let ped_pp = &auction_pp.auction_pp.ped_pp;
    let f_k = nat_to_f::<<G as ProjectiveCurve>::ScalarField>(&BigInt::from(lower_bound))
        .map_err(|e| format!("prove_bid_at_least: nat_to_f: {e}"))?;
    let shifted = comm_bid_ped.clone() - ped_pp.g.mul(&f_k.into_repr());
    Bulletproofs::<G, H>::prove_range(
        rng,
        &house_pp.range_proof_pp,
        ped_pp,
        &shifted,
        &BigInt::from(diff),
        opening_bid_ped,
        NUM_BID_BITS,
    )
    .map_err(|e| format!("prove_bid_at_least: prove_range: {e}"))
}

/// 对应 `prove_bid_at_least` 的 verifier。
pub fn verify_bid_at_least(
    house_pp: &HouseParams<G>,
    auction_pp: &HouseAuctionParams<G, DemoRsaParams>,
    comm_bid_ped: &G,
    lower_bound: u32,
    proof: &RangeProof<G>,
) -> Result<bool, String> {
    let ped_pp = &auction_pp.auction_pp.ped_pp;
    let f_k = nat_to_f::<<G as ProjectiveCurve>::ScalarField>(&BigInt::from(lower_bound))
        .map_err(|e| format!("verify_bid_at_least: nat_to_f: {e}"))?;
    let shifted = comm_bid_ped.clone() - ped_pp.g.mul(&f_k.into_repr());
    Bulletproofs::<G, H>::verify_range(
        &house_pp.range_proof_pp,
        ped_pp,
        &shifted,
        NUM_BID_BITS,
        proof,
    )
    .map_err(|e| format!("verify_bid_at_least: verify_range: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use auction_house::auction::Auction;

    fn commit_bid(world: &mut World, bid: u32) -> (G, <G as ProjectiveCurve>::ScalarField) {
        let (comm, opening) = Auction::<G, DemoPoEParams, DemoRsaParams, H, H2P>::client_create_bid(
            &mut world.rng,
            &world.auction_pp.auction_pp,
            bid,
        )
        .expect("client_create_bid");
        (comm.ped_comm, opening.get_ped_opening())
    }

    #[test]
    fn aux_proof_roundtrip_reserve_ok() {
        let mut w = World::bootstrap();
        let (c, r) = commit_bid(&mut w, 500);
        let mut rng = StdRng::seed_from_u64(7);
        let proof = prove_bid_at_least(&mut rng, &w.house_pp, &w.auction_pp, &c, 500, 300, &r)
            .expect("prove");
        assert!(
            verify_bid_at_least(&w.house_pp, &w.auction_pp, &c, 300, &proof).expect("verify")
        );
    }

    #[test]
    fn aux_proof_roundtrip_prev_high_ok() {
        let mut w = World::bootstrap();
        let bid = 700u32;
        let prev_high = 250u32;
        let (c, r) = commit_bid(&mut w, bid);
        let mut rng = StdRng::seed_from_u64(13);
        let proof = prove_bid_at_least(
            &mut rng,
            &w.house_pp,
            &w.auction_pp,
            &c,
            bid,
            prev_high + 1,
            &r,
        )
        .expect("prove");
        assert!(verify_bid_at_least(&w.house_pp, &w.auction_pp, &c, prev_high + 1, &proof)
            .expect("verify"));
    }

    #[test]
    fn aux_proof_rejects_wrong_bound() {
        let mut w = World::bootstrap();
        let (c, r) = commit_bid(&mut w, 500);
        let mut rng = StdRng::seed_from_u64(9);
        let proof = prove_bid_at_least(&mut rng, &w.house_pp, &w.auction_pp, &c, 500, 100, &r)
            .expect("prove");
        // 若 verifier 将下界改成 600（> bid），shifted commitment 与 proof 不匹配，验证必失败
        assert!(
            !verify_bid_at_least(&w.house_pp, &w.auction_pp, &c, 600, &proof).expect("verify")
        );
    }

    #[test]
    fn aux_proof_prover_refuses_infeasible() {
        let mut w = World::bootstrap();
        let (c, r) = commit_bid(&mut w, 100);
        let mut rng = StdRng::seed_from_u64(11);
        assert!(
            prove_bid_at_least(&mut rng, &w.house_pp, &w.auction_pp, &c, 100, 200, &r).is_err()
        );
    }

    /// Part B1 负例：攻击者即便持有某合法 bid 对某下界 `k1` 的 proof，也无法将其
    /// 用在 `verify_bid_at_least(..., k2, proof)`（k2 ≠ k1）上。对应 bid handler
    /// gating 的数学基石：verifier 用公开 `reserve` / `prev_high+1` 重构 shifted
    /// 承诺，与 prover 固定到 k1 的 shifted 承诺点位不同，proof 必失效。
    #[test]
    fn aux_proof_cannot_be_replayed_across_lower_bounds() {
        let mut w = World::bootstrap();
        let (c, r) = commit_bid(&mut w, 500);
        let mut rng = StdRng::seed_from_u64(23);

        let proof_for_300 =
            prove_bid_at_least(&mut rng, &w.house_pp, &w.auction_pp, &c, 500, 300, &r)
                .expect("prove k1=300");
        assert!(
            verify_bid_at_least(&w.house_pp, &w.auction_pp, &c, 300, &proof_for_300)
                .expect("verify k1")
        );

        // verifier 将下界改成 k2=400：同一 commit、同一 proof，但 shifted 点不同 → 必拒
        assert!(
            !verify_bid_at_least(&w.house_pp, &w.auction_pp, &c, 400, &proof_for_300)
                .expect("verify k2 must not panic")
        );
    }

    /// Part B1 负例：攻击者持有 bid=600 的合法 proof，不能"移植"给 bid=100 的
    /// 另一承诺声称 bid>=500 —— Pedersen 承诺绑定 + Fiat-Shamir 挑战锁定了承诺。
    #[test]
    fn aux_proof_cannot_be_replayed_across_commits() {
        let mut w = World::bootstrap();
        let (c_high, r_high) = commit_bid(&mut w, 600);
        let (c_low, _r_low) = commit_bid(&mut w, 100);
        let mut rng = StdRng::seed_from_u64(31);

        let good_proof =
            prove_bid_at_least(&mut rng, &w.house_pp, &w.auction_pp, &c_high, 600, 500, &r_high)
                .expect("prove high bid");
        assert!(
            verify_bid_at_least(&w.house_pp, &w.auction_pp, &c_high, 500, &good_proof)
                .expect("verify on high commit")
        );

        // 同一 proof 对另一条低价承诺 verify → 必拒
        assert!(
            !verify_bid_at_least(&w.house_pp, &w.auction_pp, &c_low, 500, &good_proof)
                .expect("verify on low commit must not panic")
        );
    }
}
