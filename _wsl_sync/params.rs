use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use ark_bn254::G1Projective;
use once_cell::sync::Lazy;
use rsa::{
    bigint::BigInt,
    hash_to_prime::pocklington::{PocklingtonCertParams, PocklingtonHash},
    hog::RsaGroupParams,
    poe::PoEParams,
};

pub const MOD_BITS: usize = 2048;

/// RSW / PoE 链参数 T 的"有效值"：`v = u^{2^T}` 需 **真** 2^T 次顺序平方。
/// 默认 16（约几秒）；启动时 `calibrate_time_param()` 会按目标耗时自动测速并更新。
static TIME_PARAM_CELL: AtomicU64 = AtomicU64::new(16);

/// 读取当前 T（由 `calibrate_time_param()` / `set_time_param()` 注入）。
#[inline]
pub fn time_param() -> u64 {
    TIME_PARAM_CELL.load(Ordering::Relaxed)
}

/// 手动覆盖 T（测试 / env 注入）。
pub fn set_time_param(t: u64) {
    TIME_PARAM_CELL.store(t, Ordering::Relaxed);
}

/// 自动测速：跑 N 次真 `x.power(2)` 的平均耗时，按目标秒数反推 T。
/// 优先级：`VSBMAS_TIME_PARAM`（若存在且可解析）> auto-calibrate > 默认 16。
/// `VSBMAS_TARGET_FORCE_OPEN_SECS` 默认 120；`VSBMAS_CALIBRATE_SAMPLES` 默认 200。
///
/// 为防止目标秒数乘上 1e6 后溢出（u64 范围内也不容易溢出，但按 i128 计更稳），
/// 结果 `T` 夹到 `[14, 24]` 范围，避免 T=0 或 T 爆炸导致 force-open 永远跑不完。
pub fn calibrate_time_param() -> (u64, u64 /*sq_time_us*/) {
    use rsa::hog::RsaHiddenOrderGroup;
    // 1) 手动覆盖分支。
    if let Ok(s) = std::env::var("VSBMAS_TIME_PARAM") {
        if let Ok(t) = s.trim().parse::<u64>() {
            let clamped = t.clamp(4, 32);
            set_time_param(clamped);
            return (clamped, 0);
        }
    }
    // 2) bench：200 次 x.power(2) 作为单次耗时样本。
    let samples: u64 = std::env::var("VSBMAS_CALIBRATE_SAMPLES")
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .unwrap_or(200)
        .max(10);
    let target_secs: u64 = std::env::var("VSBMAS_TARGET_FORCE_OPEN_SECS")
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .unwrap_or(120)
        .max(5);

    // 固定 seed 的 RSA 群元素（取 g=2 的 hidden-order group representative）。
    let mut x: RsaHiddenOrderGroup<DemoRsaParams> =
        RsaHiddenOrderGroup::from_nat(BigInt::from(2u32));
    let two = BigInt::from(2u32);
    let start = Instant::now();
    for _ in 0..samples {
        x = x.power(&two);
    }
    let elapsed = start.elapsed();
    let total_us = elapsed.as_micros().max(1) as u64;
    let sq_time_us = (total_us / samples).max(1);

    // total_sq = target_secs * 1e6 / sq_time_us
    let total_sq = (target_secs as u128 * 1_000_000u128) / sq_time_us as u128;
    // T = round(log2(total_sq))
    let t_f = (total_sq as f64).log2();
    let t = if t_f.is_finite() {
        t_f.round().clamp(14.0, 24.0) as u64
    } else {
        16
    };
    set_time_param(t);
    (t, sq_time_us)
}

/// 演示用：legacy sleep 节流节奏（步/秒）。Part C 真 RSW 路径不再使用；仅给旧版
/// `demo_sequential_rsw_progress` / `run_bruteforce_demo_chain` 在废弃过渡期编译通过。
#[allow(dead_code)]
pub const DEMO_SQ_PER_SEC: u64 = 500;

/// 诚实强揭进度回调：每 `FORCE_OPEN_PROGRESS_BATCH` 步聚合一次。
pub const FORCE_OPEN_PROGRESS_BATCH: u64 = 512;
pub const NUM_BID_BITS: u64 = 32;
pub const LOG_NUM_BID_BITS: u64 = 5;

pub const REWARD_SELF_OPEN: u32 = 5;
pub const REWARD_FORCE_OPEN: u32 = 5;

pub const T_BID_COLLECTION_SECS: u64 = 60;
pub const T_BID_SELF_OPEN_SECS: u64 = 60;
pub const T_BID_FORCE_OPEN_SECS: u64 = 30;

pub fn t_bid_collection() -> Duration {
    Duration::from_secs(T_BID_COLLECTION_SECS)
}
pub fn t_bid_self_open() -> Duration {
    Duration::from_secs(T_BID_SELF_OPEN_SECS)
}

/// RSA 群参数：与 `~/riggs/auction_house/src/house.rs` 测试模块 `TestRsaParams::M` 一致。
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct DemoRsaParams;

impl RsaGroupParams for DemoRsaParams {
    const G: Lazy<BigInt> = Lazy::new(|| BigInt::from(2));
    const M: Lazy<BigInt> = Lazy::new(|| {
        BigInt::from_str("2519590847565789349402718324004839857142928212620403202777713783604366202070\
                          7595556264018525880784406918290641249515082189298559149176184502808489120072\
                          8449926873928072877767359714183472702618963750149718246911650776133798590957\
                          0009733045974880842840179742910064245869181719511874612151517265463228221686\
                          9987549182422433637259085141865462043576798423387184774447920739934236584823\
                          8242811981638150106748104516603773060562016196762561338441436038339044149526\
                          3443219011465754445417842402092461651572335077870774981712577246796292638635\
                          6373289912154831438167899885040445364023527381951378636564391212010397122822\
                          120720357")
            .unwrap()
    });
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct DemoPoEParams;
impl PoEParams for DemoPoEParams {
    const HASH_TO_PRIME_ENTROPY: usize = 256;
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct DemoPocklingtonParams;
impl PocklingtonCertParams for DemoPocklingtonParams {
    const NONCE_SIZE: usize = 16;
    const MAX_STEPS: usize = 5;
    const INCLUDE_SOLIDITY_WITNESSES: bool = true;
}

pub type G = G1Projective;
pub type H = sha3::Keccak256;
pub type H2P = PocklingtonHash<DemoPocklingtonParams, H>;

/// 与 `~/riggs/solidity/benches/auction_house_tc.rs` 中 `order` 一致。
pub static DEMO_RSA_ORDER: Lazy<BigInt> = Lazy::new(|| {
    BigInt::from_str(
        "220221485961027482895807132690296630677486844071857248828102639779900826037\
                522817575171387188561253238223028895754955597267595588137098207226627715313\
                686049237996261509248457831215460282155642105163463527516323185300916088248\
                789771290659167975569920900762065967420098972398211591577160443767729150998\
                814909357423098257777268264247365382899876367590978535154987039555696635449\
                479033630746473829352109992523017984438324929520913675495666843818457268371\
                447341902888262499596643623902905552015345991769002075550880559006205833829\
                780310095180709267067428790477468978775910299274821078714680960191595657081\
                71734442332552864",
    )
    .unwrap()
});
