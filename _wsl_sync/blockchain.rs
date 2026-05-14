//! 简易演示链（与 `blockchain_demo/riggs_blockchain_demo.py` 的哈希与 PoW 规则一致）。
//! 交易类型命名对齐 `vsbmas_core::events::Event`。

use hex;
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

pub const GENESIS_PREVIOUS: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Clone, Debug, Serialize)]
pub struct BlockRecord {
    pub index: u64,
    pub timestamp: f64,
    pub transactions: Vec<Value>,
    pub previous_hash: String,
    pub nonce: u64,
    pub difficulty: u32,
    pub hash: String,
}

pub struct DemoBlockchain {
    pub difficulty: u32,
    pub chain: Vec<BlockRecord>,
    pub pending: Vec<Value>,
}

fn now_ts() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}

fn sort_json_value(v: &Value) -> Value {
    match v {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let mut new_map = serde_json::Map::new();
            for k in keys {
                new_map.insert(k.clone(), sort_json_value(&map[k]));
            }
            Value::Object(new_map)
        }
        Value::Array(arr) => Value::Array(arr.iter().map(sort_json_value).collect()),
        _ => v.clone(),
    }
}

fn canonical_tx_json(transactions: &[Value]) -> String {
    let normalized: Vec<Value> = transactions.iter().map(sort_json_value).collect();
    serde_json::to_string(&normalized).expect("tx json")
}

pub fn calculate_hash(
    index: u64,
    timestamp: f64,
    transactions: &[Value],
    previous_hash: &str,
    nonce: u64,
    difficulty: u32,
) -> String {
    let tx = canonical_tx_json(transactions);
    let payload = format!(
        "{index}|{ts:.6}|{tx}|{previous_hash}|{nonce}|{difficulty}",
        ts = timestamp
    );
    let mut h = Sha256::new();
    h.update(payload.as_bytes());
    hex::encode(h.finalize())
}

pub fn hash_meets_difficulty(block_hash: &str, difficulty: u32) -> bool {
    if difficulty == 0 {
        return true;
    }
    let prefix = "0".repeat(difficulty as usize);
    block_hash.starts_with(&prefix)
}

impl DemoBlockchain {
    pub fn empty(difficulty: u32) -> Self {
        Self {
            difficulty: difficulty.max(1),
            chain: Vec::new(),
            pending: Vec::new(),
        }
    }

    /// 清空链并挖出创世区块。
    pub fn mine_genesis(&mut self) {
        self.chain.clear();
        self.pending.clear();
        let ts = now_ts();
        let mut nonce = 0u64;
        let mut hash = calculate_hash(0, ts, &[], GENESIS_PREVIOUS, nonce, self.difficulty);
        while !hash_meets_difficulty(&hash, self.difficulty) {
            nonce += 1;
            hash = calculate_hash(0, ts, &[], GENESIS_PREVIOUS, nonce, self.difficulty);
        }
        self.chain.push(BlockRecord {
            index: 0,
            timestamp: ts,
            transactions: vec![],
            previous_hash: GENESIS_PREVIOUS.to_string(),
            nonce,
            difficulty: self.difficulty,
            hash,
        });
    }

    pub fn add_pending(&mut self, tx: Value) {
        self.pending.push(tx);
    }

    pub fn mine_pending_block(&mut self) -> Result<(), &'static str> {
        if self.pending.is_empty() {
            return Err("no pending transactions");
        }
        let prev = self.chain.last().ok_or("empty chain")?;
        let new_index = prev.index + 1;
        let ts = now_ts();
        let txs = std::mem::take(&mut self.pending);
        let prev_hash = prev.hash.clone();
        let mut nonce = 0u64;
        let mut hash = calculate_hash(new_index, ts, &txs, &prev_hash, nonce, self.difficulty);
        while !hash_meets_difficulty(&hash, self.difficulty) {
            nonce += 1;
            hash = calculate_hash(new_index, ts, &txs, &prev_hash, nonce, self.difficulty);
        }
        self.chain.push(BlockRecord {
            index: new_index,
            timestamp: ts,
            transactions: txs,
            previous_hash: prev_hash,
            nonce,
            difficulty: self.difficulty,
            hash,
        });
        Ok(())
    }

    pub fn is_chain_valid(&self) -> (bool, String) {
        if self.chain.is_empty() {
            return (false, "链为空".into());
        }
        let genesis = &self.chain[0];
        if genesis.index != 0 {
            return (false, "创世区块 index 必须为 0".into());
        }
        if genesis.previous_hash != GENESIS_PREVIOUS {
            return (false, "创世区块 previous_hash 无效".into());
        }
        let exp = calculate_hash(
            genesis.index,
            genesis.timestamp,
            &genesis.transactions,
            &genesis.previous_hash,
            genesis.nonce,
            genesis.difficulty,
        );
        if exp != genesis.hash {
            return (
                false,
                "创世区块 hash 不匹配（可能被篡改或损坏）".into(),
            );
        }
        if !hash_meets_difficulty(&genesis.hash, genesis.difficulty) {
            return (false, "创世区块不满足 PoW 难度".into());
        }

        for i in 1..self.chain.len() {
            let current = &self.chain[i];
            let previous = &self.chain[i - 1];
            if current.previous_hash != previous.hash {
                return (
                    false,
                    format!(
                        "区块 #{} 的 previous_hash 与前一区块 hash 不一致",
                        current.index
                    ),
                );
            }
            let exp_h = calculate_hash(
                current.index,
                current.timestamp,
                &current.transactions,
                &current.previous_hash,
                current.nonce,
                current.difficulty,
            );
            if exp_h != current.hash {
                return (
                    false,
                    format!(
                        "区块 #{} 存储的 hash 与根据内容重算不一致（篡改检测）",
                        current.index
                    ),
                );
            }
            if !hash_meets_difficulty(&current.hash, current.difficulty) {
                return (
                    false,
                    format!("区块 #{} 不满足 PoW 难度", current.index),
                );
            }
        }
        (true, "整条链校验通过".into())
    }

    /// 演示篡改：修改链上最早的 `BidSubmitted.bid_commitment_preview`；
    /// 若没有（仅有真实打包的 `VsbmasRoundCommitted`），则篡改其 `participants[]` 中首条预览字段。
    pub fn tamper_first_bid_preview(&mut self) -> bool {
        for block in &mut self.chain {
            for tx in &mut block.transactions {
                if let Value::Object(ref mut map) = tx {
                    if map.get("type").and_then(|t| t.as_str()) == Some("BidSubmitted") {
                        map.insert(
                            "bid_commitment_preview".into(),
                            Value::String("被恶意篡改的摘要".into()),
                        );
                        return true;
                    }
                    if map.get("type").and_then(|t| t.as_str()) == Some("VsbmasRoundCommitted") {
                        if let Some(Value::Array(parts)) = map.get_mut("participants") {
                            for p in parts.iter_mut() {
                                if let Value::Object(ref mut pm) = p {
                                    if pm.contains_key("bid_commitment_preview") {
                                        pm.insert(
                                            "bid_commitment_preview".into(),
                                            Value::String("被恶意篡改的摘要".into()),
                                        );
                                        return true;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        false
    }

    /// 与 Python CLI `sample_riggs_transactions` + 三区块打包一致。
    pub fn run_classroom_demo_sequence(&mut self) {
        self.mine_genesis();
        self.add_pending(serde_json::json!({
            "type": "AuctionCreated",
            "auction_id": 1,
            "item_name": "课堂演示拍卖品",
            "reserve_price": 100
        }));
        self.add_pending(serde_json::json!({
            "type": "BidSubmitted",
            "auction_id": 1,
            "user_id": 42,
            "bid_commitment_preview": "a1b2c3d4…（Pedersen commitment 摘要）",
            "constraint_ok": true
        }));
        let _ = self.mine_pending_block();

        self.add_pending(serde_json::json!({
            "type": "SelfOpened",
            "auction_id": 1,
            "user_id": 42,
            "bid_revealed": 150
        }));
        self.add_pending(serde_json::json!({
            "type": "Settled",
            "auction_id": 1,
            "price": 150,
            "winners": [42]
        }));
        let _ = self.mine_pending_block();

        self.add_pending(serde_json::json!({
            "type": "VerificationFailed",
            "actor": 99,
            "reason": "tampered_range_proof",
            "auction_id": 1
        }));
        let _ = self.mine_pending_block();
    }
}
