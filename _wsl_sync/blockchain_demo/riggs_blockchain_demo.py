#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Riggs / VSBMAS 本地简易区块链演示（CLI）。

交易类型命名对齐真实后端事件（见 _wsl_sync/events.rs）：AuctionCreated、BidSubmitted、
SelfOpened、ForceOpened、Settled、VerificationFailed。

仅使用 Python 标准库：hashlib、json、time、dataclasses、argparse。
"""

from __future__ import annotations

import argparse
import hashlib
import json
import time
from dataclasses import asdict, dataclass, field
from typing import List, Tuple


GENESIS_PREVIOUS = "0" * 64


def _canonical_tx_json(transactions: List[dict]) -> str:
    return json.dumps(transactions, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def calculate_hash(
    index: int,
    timestamp: float,
    transactions: List[dict],
    previous_hash: str,
    nonce: int,
    difficulty: int,
) -> str:
    """对区块载荷（不含当前 hash 字段）做 SHA-256，返回 64 位十六进制小写字符串。"""
    payload = (
        f"{index}|{timestamp:.6f}|{_canonical_tx_json(transactions)}|"
        f"{previous_hash}|{nonce}|{difficulty}"
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def hash_meets_difficulty(block_hash: str, difficulty: int) -> bool:
    """
    简化 PoW：要求十六进制 digest 的前 difficulty 个字符均为 '0'。
    difficulty=3 表示前缀 "000..."（课堂演示足够快）。
    """
    if difficulty <= 0:
        return True
    prefix = "0" * difficulty
    return block_hash.startswith(prefix)


@dataclass
class Block:
    index: int
    timestamp: float
    transactions: List[dict]
    previous_hash: str
    nonce: int
    difficulty: int
    hash: str

    def to_dict(self) -> dict:
        d = asdict(self)
        return d


@dataclass
class Blockchain:
    chain: List[Block] = field(default_factory=list)
    difficulty: int = 3
    pending_transactions: List[dict] = field(default_factory=list)

    def create_genesis_block(self) -> Block:
        ts = time.time()
        nonce = 0
        h = calculate_hash(0, ts, [], GENESIS_PREVIOUS, nonce, self.difficulty)
        while not hash_meets_difficulty(h, self.difficulty):
            nonce += 1
            h = calculate_hash(0, ts, [], GENESIS_PREVIOUS, nonce, self.difficulty)
        genesis = Block(
            index=0,
            timestamp=ts,
            transactions=[],
            previous_hash=GENESIS_PREVIOUS,
            nonce=nonce,
            difficulty=self.difficulty,
            hash=h,
        )
        self.chain = [genesis]
        return genesis

    def get_latest_block(self) -> Block:
        return self.chain[-1]

    def add_transaction(self, tx: dict) -> None:
        if "type" not in tx:
            raise ValueError("transaction 必须包含 type 字段（Riggs 事件名）")
        self.pending_transactions.append(tx)

    def mine_pending_block(self) -> Block:
        if not self.pending_transactions:
            raise ValueError("没有待打包交易，请先 add_transaction")
        latest = self.get_latest_block()
        new_index = latest.index + 1
        ts = time.time()
        txs = list(self.pending_transactions)
        self.pending_transactions.clear()
        nonce = 0
        h = calculate_hash(new_index, ts, txs, latest.hash, nonce, self.difficulty)
        while not hash_meets_difficulty(h, self.difficulty):
            nonce += 1
            h = calculate_hash(new_index, ts, txs, latest.hash, nonce, self.difficulty)
        block = Block(
            index=new_index,
            timestamp=ts,
            transactions=txs,
            previous_hash=latest.hash,
            nonce=nonce,
            difficulty=self.difficulty,
            hash=h,
        )
        self.chain.append(block)
        return block

    def is_chain_valid(self) -> Tuple[bool, str]:
        if not self.chain:
            return False, "链为空"
        genesis = self.chain[0]
        if genesis.index != 0:
            return False, "创世区块 index 必须为 0"
        if genesis.previous_hash != GENESIS_PREVIOUS:
            return False, "创世区块 previous_hash 无效"
        exp = calculate_hash(
            genesis.index,
            genesis.timestamp,
            genesis.transactions,
            genesis.previous_hash,
            genesis.nonce,
            genesis.difficulty,
        )
        if exp != genesis.hash:
            return False, f"创世区块 hash 不匹配（可能被篡改或损坏）"
        if not hash_meets_difficulty(genesis.hash, genesis.difficulty):
            return False, "创世区块不满足 PoW 难度"

        for i in range(1, len(self.chain)):
            current = self.chain[i]
            previous = self.chain[i - 1]
            if current.previous_hash != previous.hash:
                return (
                    False,
                    f"区块 #{current.index} 的 previous_hash 与前一区块 hash 不一致",
                )
            exp_h = calculate_hash(
                current.index,
                current.timestamp,
                current.transactions,
                current.previous_hash,
                current.nonce,
                current.difficulty,
            )
            if exp_h != current.hash:
                return (
                    False,
                    f"区块 #{current.index} 存储的 hash 与根据内容重算不一致（篡改检测）",
                )
            if not hash_meets_difficulty(current.hash, current.difficulty):
                return False, f"区块 #{current.index} 不满足 PoW 难度"
        return True, "整条链校验通过"


def sample_riggs_transactions() -> List[dict]:
    """与 VSBMAS 业务一致的示例交易（摘要级字段，非完整证明原文）。"""
    return [
        {
            "type": "AuctionCreated",
            "auction_id": 1,
            "item_name": "课堂演示拍卖品",
            "reserve_price": 100,
        },
        {
            "type": "BidSubmitted",
            "auction_id": 1,
            "user_id": 42,
            "bid_commitment_preview": "a1b2c3d4…（Pedersen commitment 摘要）",
            "constraint_ok": True,
        },
        {
            "type": "SelfOpened",
            "auction_id": 1,
            "user_id": 42,
            "bid_revealed": 150,
        },
        {
            "type": "Settled",
            "auction_id": 1,
            "price": 150,
            "winners": [42],
        },
    ]


def print_chain(bc: Blockchain, max_tx_preview: int = 2) -> None:
    print(f"\n=== 当前区块链（难度 PoW 前缀零十六进制位数={bc.difficulty}）===\n")
    for b in bc.chain:
        print(f"区块 #{b.index}")
        print(f"  timestamp:    {b.timestamp}")
        print(f"  previousHash: {b.previous_hash}")
        print(f"  nonce:        {b.nonce}")
        print(f"  hash:         {b.hash}")
        print(f"  transactions: {len(b.transactions)} 笔")
        for j, tx in enumerate(b.transactions[:max_tx_preview]):
            print(f"    [{j}] {json.dumps(tx, ensure_ascii=False)}")
        if len(b.transactions) > max_tx_preview:
            print(f"    ... 另有 {len(b.transactions) - max_tx_preview} 笔")
        print()


def run_demo(difficulty: int) -> None:
    print("=== Riggs 审计事件 → 简易区块链演示 ===\n")

    bc = Blockchain(difficulty=difficulty)
    print("1) 创建并挖矿创世区块（genesis block）…")
    bc.create_genesis_block()
    print(f"   创世区块 hash: {bc.chain[0].hash}\n")

    samples = sample_riggs_transactions()
    print("2) 将 Riggs 业务记录作为 transaction 加入内存池并逐块挖矿…")
    for tx in samples[:2]:
        bc.add_transaction(tx)
    b1 = bc.mine_pending_block()
    print(f"   已挖出区块 #1，hash={b1.hash[:24]}…，nonce={b1.nonce}")

    for tx in samples[2:]:
        bc.add_transaction(tx)
    b2 = bc.mine_pending_block()
    print(f"   已挖出区块 #2，hash={b2.hash[:24]}…，nonce={b2.nonce}")

    # 单独一笔 VerificationFailed 进新区块
    bc.add_transaction(
        {
            "type": "VerificationFailed",
            "actor": 99,
            "reason": "tampered_range_proof",
            "auction_id": 1,
        }
    )
    b3 = bc.mine_pending_block()
    print(f"   已挖出区块 #3（含 VerificationFailed），hash={b3.hash[:24]}…，nonce={b3.nonce}\n")

    print_chain(bc)

    ok, msg = bc.is_chain_valid()
    print(f"3) 校验整条链: valid={ok} — {msg}\n")

    # 篡改：修改区块 #1 内一笔交易的字段
    print("4) 模拟篡改：修改区块 #1 中 BidSubmitted 的 bid_commitment_preview …")
    target = None
    for blk in bc.chain:
        for tx in blk.transactions:
            if tx.get("type") == "BidSubmitted":
                target = tx
                break
        if target is not None:
            break
    if target is None:
        print("   （未找到 BidSubmitted，跳过篡改演示）")
    else:
        old = target.get("bid_commitment_preview")
        target["bid_commitment_preview"] = "被恶意篡改的摘要"
        print(f"   原值: {old}")
        print(f"   新值: {target['bid_commitment_preview']}\n")

    ok2, msg2 = bc.is_chain_valid()
    print(f"5) 再次校验: valid={ok2} — {msg2}")
    print("\n说明：篡改交易内容后，根据 index/timestamp/transactions/previous_hash/nonce 重算的")
    print("      SHA-256 与区块内保存的 hash 不一致，链验证失败 — 即篡改检测。\n")

    # ForceOpened 示例（单独演示类型覆盖）
    print("（补充）事件类型 ForceOpened 示例交易字段：")
    print(
        json.dumps(
            {
                "type": "ForceOpened",
                "auction_id": 1,
                "user_id": 7,
                "bid_revealed": 120,
                "note": "RSW/PoE 强揭完成（仅演示摘要）",
            },
            ensure_ascii=False,
        )
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Riggs / VSBMAS 本地区块链核心机制 CLI 演示"
    )
    parser.add_argument(
        "command",
        nargs="?",
        default="demo",
        choices=["demo"],
        help="demo：完整演示创世、挖矿、校验、篡改检测（默认）",
    )
    parser.add_argument(
        "--difficulty",
        type=int,
        default=3,
        help="PoW：要求 block hash（hex）前缀连续 0 的个数，默认 3",
    )
    args = parser.parse_args()
    if args.difficulty < 1:
        parser.error("difficulty 至少为 1")
    if args.command == "demo":
        run_demo(args.difficulty)


if __name__ == "__main__":
    main()
