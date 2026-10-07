##################################################
# author:   mrbacco <mrbacco04@gmail.com>
# date:     2026-10-07
# filename: proofchain/block.py
#
# blocks: a header (linked to the previous block
# by hash, committing to its transactions by
# merkle root) secured with proof-of-work
##################################################

import threading
from dataclasses import dataclass, field

from proofchain.transaction import Transaction
from proofchain.utils import ValidationError, canonical_json, sha3_hex

GENESIS_TIMESTAMP = 1577836800000  # 2020-01-01T00:00:00Z, fixed so every node shares one genesis
GENESIS_PREV_HASH = "0" * 64
MAX_TXS_PER_BLOCK = 500
MAX_MINER_LENGTH = 64


def merkle_root(tx_ids: list[str]) -> str:
    if not tx_ids:
        return sha3_hex(b"")
    level = list(tx_ids)
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [sha3_hex((level[i] + level[i + 1]).encode()) for i in range(0, len(level), 2)]
    return level[0]


@dataclass
class Block():
    index: int
    timestamp: int
    prev_hash: str
    difficulty: int
    miner: str
    transactions: list[Transaction] = field(default_factory=list)
    nonce: int = 0
    merkle_root: str = ""
    hash: str = ""

    def __post_init__(self):
        if not self.merkle_root:
            self.merkle_root = merkle_root([tx.tx_id for tx in self.transactions])
        if not self.hash:
            self.hash = self.compute_hash()

    @classmethod
    def genesis(cls) -> "Block":
        return cls(index=0, timestamp=GENESIS_TIMESTAMP, prev_hash=GENESIS_PREV_HASH, difficulty=0, miner="genesis")

    def header(self) -> dict:
        return {
            "index": self.index,
            "timestamp": self.timestamp,
            "prev_hash": self.prev_hash,
            "merkle_root": self.merkle_root,
            "difficulty": self.difficulty,
            "miner": self.miner,
            "nonce": self.nonce,
        }

    def compute_hash(self) -> str:
        return sha3_hex(canonical_json(self.header()))

    def meets_difficulty(self) -> bool:
        return self.hash.startswith("0" * self.difficulty)

    def mine(self, stop_event: threading.Event | None = None) -> bool:
        # increments the nonce until the hash has `difficulty` leading zeros;
        # returns False if stop_event is set first (e.g. a peer found the block)
        self.nonce = 0
        self.hash = self.compute_hash()
        while not self.meets_difficulty():
            if stop_event is not None and self.nonce % 10_000 == 0 and stop_event.is_set():
                return False
            self.nonce += 1
            self.hash = self.compute_hash()
        return True

    def to_dict(self) -> dict:
        return {
            **self.header(),
            "hash": self.hash,
            "transactions": [tx.to_dict() for tx in self.transactions],
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Block":
        try:
            return cls(
                index=data["index"],
                timestamp=data["timestamp"],
                prev_hash=data["prev_hash"],
                difficulty=data["difficulty"],
                miner=data["miner"],
                transactions=[Transaction.from_dict(tx) for tx in data["transactions"]],
                nonce=data["nonce"],
                merkle_root=data["merkle_root"],
                hash=data["hash"],
            )
        except (KeyError, TypeError) as exc:
            raise ValidationError(f"malformed block: {exc}") from exc

    def __str__(self):
        return (
            f"block #{self.index} {self.hash[:16]}... "
            f"(prev {self.prev_hash[:16]}..., {len(self.transactions)} txs, nonce {self.nonce})"
        )
