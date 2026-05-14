#![allow(dead_code)]

pub mod params;      // md 05 填：MOD_BITS / TIME_PARAM / NUM_BID_BITS / 时长等
pub mod house;       // md 05 填：AuctionHouse 类型别名 + 初始化
pub mod serialize;   // md 06 填：CanonicalSerialize → hex 辅助

pub mod prelude {
    pub use super::{house::*, params::*, serialize::*};
}
