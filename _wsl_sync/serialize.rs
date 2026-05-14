use ark_ec::ProjectiveCurve;
use ark_serialize::CanonicalSerialize;

use auction_house::house::BidProposal;
use range_proofs::bulletproofs::Proof as RangeProof;
use rsa::{
    bigint::BigInt,
    hash_to_prime::HashToPrime,
    hog::{RsaGroupParams, RsaHiddenOrderGroup},
    poe::Proof as PoEProof,
};
use timed_commitments::basic_tc::{Comm as BasicTCComm, Opening as BasicTCOpening};
use timed_commitments::lazy_tc::{Comm as TCComm, Opening as LazyTCOpening};

fn ark_bytes<T: CanonicalSerialize>(v: &T) -> Vec<u8> {
    let mut buf = Vec::with_capacity(v.serialized_size());
    v.serialize(&mut buf).expect("canonical serialize");
    buf
}

pub fn curve_hex<G: ProjectiveCurve>(p: &G) -> String {
    hex::encode(ark_bytes(p))
}

pub fn bigint_hex(n: &BigInt) -> String {
    hex::encode(n.to_bytes_be().1)
}

pub fn hog_hex<RsaP: RsaGroupParams>(h: &RsaHiddenOrderGroup<RsaP>) -> String {
    bigint_hex(&h.n)
}

pub fn basic_tc_comm_hex<RsaP: RsaGroupParams>(c: &BasicTCComm<RsaP>) -> String {
    format!("{}|{}", hog_hex(&c.x), hex::encode(&c.ct))
}

pub fn tc_comm_hex<G, RsaP>(c: &TCComm<G, RsaP>) -> (String, String)
where
    G: ProjectiveCurve,
    RsaP: RsaGroupParams,
{
    (curve_hex(&c.ped_comm), basic_tc_comm_hex(&c.tc_comm))
}

pub fn range_proof_hex<G: ProjectiveCurve>(p: &RangeProof<G>) -> (String, usize) {
    let mut buf = Vec::new();
    p.comm_bits.serialize(&mut buf).unwrap();
    p.comm_blind.serialize(&mut buf).unwrap();
    p.comm_lc1.serialize(&mut buf).unwrap();
    p.comm_lc2.serialize(&mut buf).unwrap();
    p.t_x.serialize(&mut buf).unwrap();
    p.r_t_x.serialize(&mut buf).unwrap();
    p.r_ab.serialize(&mut buf).unwrap();
    (p.comm_ipa.len() as u32).serialize(&mut buf).unwrap();
    for (a, b) in &p.comm_ipa {
        a.serialize(&mut buf).unwrap();
        b.serialize(&mut buf).unwrap();
    }
    p.base_a.serialize(&mut buf).unwrap();
    p.base_b.serialize(&mut buf).unwrap();
    let size = buf.len();
    (hex::encode(buf), size)
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct BidProposalView {
    pub ped_commit_hex: String,
    pub tc_commit_hex: String,
    pub range_proof_bid_hex: String,
    pub range_proof_bid_size: usize,
    pub range_proof_balance_hex: String,
    pub range_proof_balance_size: usize,
    pub total_proof_size_bytes: usize,
}

pub fn bid_proposal_view<G, RsaP>(b: &BidProposal<G, RsaP>) -> BidProposalView
where
    G: ProjectiveCurve,
    RsaP: RsaGroupParams,
{
    let (ped_hex, tc_hex) = tc_comm_hex(&b.comm_bid);
    let (rp_bid_hex, rp_bid_size) = range_proof_hex(&b.range_proof_bid);
    let (rp_bal_hex, rp_bal_size) = range_proof_hex(&b.range_proof_balance);
    BidProposalView {
        ped_commit_hex: ped_hex,
        tc_commit_hex: tc_hex,
        range_proof_bid_hex: rp_bid_hex,
        range_proof_bid_size: rp_bid_size,
        range_proof_balance_hex: rp_bal_hex,
        range_proof_balance_size: rp_bal_size,
        total_proof_size_bytes: rp_bid_size + rp_bal_size,
    }
}

/// Part B：面向 `bid >= reserve_price` 与 `bid > prev_round_high_bid` 的附加 ZK range proof 视图。
///
/// 每个证明都是对"承诺位移"后的 Pedersen commitment（`C_bid - g·k`）所做的
/// Bulletproofs range-in-`[0, 2^NUM_BID_BITS)` 证明，等价于电路级约束
/// `bid - k ∈ [0, 2^NUM_BID_BITS)`，即 `bid >= k`。
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, Default)]
pub struct BidConstraintProofs {
    pub reserve_price: u32,
    pub reserve_proof_hex: String,
    pub reserve_proof_size: usize,
    pub reserve_verify_ok: bool,
    #[serde(default)]
    pub prev_round_high_bid: Option<u32>,
    #[serde(default)]
    pub prev_proof_hex: Option<String>,
    #[serde(default)]
    pub prev_proof_size: Option<usize>,
    #[serde(default)]
    pub prev_verify_ok: Option<bool>,
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, Default)]
pub struct TcOpeningView {
    pub mode: String,
    pub opening_hex: String,
    /// RSW time parameter T (total sequential squarings = 2^T).
    #[serde(default)]
    pub time_param_t: Option<u64>,
    #[serde(default)]
    pub rsw_total_sequential_steps: Option<String>,
    #[serde(default)]
    pub modulus_bits: Option<usize>,
    #[serde(default)]
    pub poe_challenge_l_hex: Option<String>,
    #[serde(default)]
    pub poe_quotient_q_hex: Option<String>,
    #[serde(default)]
    pub computation_ms: Option<u64>,
    #[serde(default)]
    pub poe_verify_ok: Option<bool>,
    /// Part B2：true 表示强揭走的是真实顺序平方 + PoE（无陷门，无 timing 模拟）。
    /// 对 SELF opening 无意义，保持 None。
    #[serde(default)]
    pub honest_rsw: Option<bool>,
    /// Part B2：true 表示本次 `computation_ms` / `ForceOpenProgress` 的耗时**仅**
    /// 用于节流模拟（B2 降级路径）；false 表示真实顺序平方（无降级，v3 默认）。
    /// 对 SELF opening 无意义，保持 None。
    #[serde(default)]
    pub demo_simulated_timing: Option<bool>,
}

#[derive(Clone, Debug, Default)]
pub struct TcOpeningMeta {
    pub computation_ms: Option<u64>,
    pub time_param_t: Option<u64>,
    pub modulus_bits: Option<usize>,
    pub poe_verify_ok: Option<bool>,
    /// Part B2：是否诚实顺序 RSW（无陷门）。
    pub honest_rsw: Option<bool>,
    /// Part B2：是否为 timing 模拟的降级路径。
    pub demo_simulated_timing: Option<bool>,
}

pub fn tc_opening_view<G, RsaP, H2P>(o: &LazyTCOpening<G, RsaP, H2P>) -> TcOpeningView
where
    G: ProjectiveCurve,
    RsaP: RsaGroupParams,
    H2P: HashToPrime,
{
    tc_opening_view_with_meta(o, TcOpeningMeta::default())
}

pub fn tc_opening_view_with_meta<G, RsaP, H2P>(
    o: &LazyTCOpening<G, RsaP, H2P>,
    meta: TcOpeningMeta,
) -> TcOpeningView
where
    G: ProjectiveCurve,
    RsaP: RsaGroupParams,
    H2P: HashToPrime,
{
    let mut v = match &o.tc_opening {
        BasicTCOpening::SELF(n) => TcOpeningView {
            mode: "self".to_string(),
            opening_hex: bigint_hex(n),
            time_param_t: None,
            rsw_total_sequential_steps: None,
            modulus_bits: None,
            poe_challenge_l_hex: None,
            poe_quotient_q_hex: None,
            computation_ms: None,
            poe_verify_ok: None,
            honest_rsw: None,
            demo_simulated_timing: None,
        },
        BasicTCOpening::FORCE(y, proof) => TcOpeningView {
            mode: "force".to_string(),
            opening_hex: format!("{}|poe:{}", hog_hex(y), poe_proof_hex(proof)),
            poe_challenge_l_hex: Some(bigint_hex(&proof.l)),
            poe_quotient_q_hex: Some(hog_hex(&proof.q)),
            ..Default::default()
        },
    };
    v.computation_ms = meta.computation_ms;
    v.time_param_t = meta.time_param_t;
    v.modulus_bits = meta.modulus_bits;
    v.poe_verify_ok = meta.poe_verify_ok;
    v.honest_rsw = meta.honest_rsw;
    v.demo_simulated_timing = meta.demo_simulated_timing;
    if let (Some(t), Some(bits)) = (meta.time_param_t, meta.modulus_bits) {
        if t < 128 {
            let steps = 1u128 << t;
            v.rsw_total_sequential_steps = Some(steps.to_string());
        } else {
            v.rsw_total_sequential_steps = Some(format!("2^{t}"));
        }
        let _ = bits; // already in meta
    }
    v
}

fn poe_proof_hex<RsaP: RsaGroupParams, H2P: HashToPrime>(p: &PoEProof<RsaP, H2P>) -> String {
    format!("q:{}|l:{}", hog_hex(&p.q), bigint_hex(&p.l))
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct ParamsSummary {
    pub mod_bits: usize,
    pub time_param: u64,
    pub num_bid_bits: u64,
    pub log_num_bid_bits: u64,
    pub reward_self_open: u32,
    pub reward_force_open: u32,
    pub t_bid_collection_secs: u64,
    pub t_bid_self_open_secs: u64,
}

pub fn params_summary() -> ParamsSummary {
    use crate::params::*;
    ParamsSummary {
        mod_bits: MOD_BITS,
        time_param: time_param(),
        num_bid_bits: NUM_BID_BITS,
        log_num_bid_bits: LOG_NUM_BID_BITS,
        reward_self_open: REWARD_SELF_OPEN,
        reward_force_open: REWARD_FORCE_OPEN,
        t_bid_collection_secs: T_BID_COLLECTION_SECS,
        t_bid_self_open_secs: T_BID_SELF_OPEN_SECS,
    }
}
