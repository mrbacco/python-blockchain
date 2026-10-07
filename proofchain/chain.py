##################################################
# author:   mrbacco <mrbacco04@gmail.com>
# date:     2026-10-07
# filename: proofchain/chain.py
#
# the ledger: list of blocks, the state derived
# from them (proof registry with disputes, and
# identities), the mempool of pending
# transactions, full validation, longest-valid-
# chain consensus and JSON persistence
##################################################

import json
import os
import threading
from dataclasses import asdict, dataclass, field, replace
from pathlib import Path

from proofchain.block import MAX_MINER_LENGTH, MAX_TXS_PER_BLOCK, Block, merkle_root
from proofchain.perceptual import hamming_distance
from proofchain.transaction import DISPUTE, IDENTITY, REGISTER, REVOKE, Transaction
from proofchain.utils import ValidationError, is_hex_digest, now_ms

DEFAULT_DIFFICULTY = 4
MAX_FUTURE_DRIFT_MS = 2 * 60 * 60 * 1000  # blocks may not be dated more than 2h ahead
PENDING = -1  # block_index used for records that only exist in the mempool


@dataclass(frozen=True)
class DisputeRecord():
    disputer: str
    reason: str
    timestamp: int
    tx_id: str
    block_index: int
    evidence: str | None = None
    evidence_timestamp: int | None = None  # when the disputer registered their evidence


@dataclass(frozen=True)
class ProofRecord():
    content_hash: str
    owner: str
    public_key: str
    metadata: dict
    timestamp: int
    tx_id: str
    block_index: int
    perceptual_hash: str | None = None
    derived_from: str | None = None
    revoked: bool = False
    revoked_at: int | None = None
    revoke_tx_id: str | None = None
    disputes: tuple[DisputeRecord, ...] = ()

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class IdentityRecord():
    address: str
    public_key: str
    name: str
    domain: str | None
    timestamp: int
    tx_id: str
    block_index: int

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class LedgerState():
    # records are immutable, so copying the dicts is enough to branch the state
    registry: dict[str, ProofRecord] = field(default_factory=dict)
    identities: dict[str, IdentityRecord] = field(default_factory=dict)

    def copy(self) -> "LedgerState":
        return LedgerState(dict(self.registry), dict(self.identities))


def apply_transaction(state: LedgerState, tx: Transaction, block_index: int) -> None:
    # state-transition rules; mutates `state`
    if tx.tx_type == IDENTITY:
        # an address may update its identity at any time; the latest one counts
        state.identities[tx.owner] = IdentityRecord(
            address=tx.owner,
            public_key=tx.public_key,
            name=tx.metadata["name"],
            domain=tx.metadata.get("domain"),
            timestamp=tx.timestamp,
            tx_id=tx.tx_id,
            block_index=block_index,
        )
        return

    registry = state.registry
    existing = registry.get(tx.content_hash)
    if tx.tx_type == REGISTER:
        if existing is not None and not existing.revoked:
            raise ValidationError(f"content {tx.content_hash} is already registered by {existing.owner}")
        if tx.derived_from is not None:
            original = registry.get(tx.derived_from)
            if original is None or original.revoked:
                raise ValidationError(f"derived_from {tx.derived_from} is not an active registration")
            if original.owner != tx.owner:
                raise ValidationError("derived_from must reference one of your own registrations")
        registry[tx.content_hash] = ProofRecord(
            content_hash=tx.content_hash,
            owner=tx.owner,
            public_key=tx.public_key,
            metadata=dict(tx.metadata),
            timestamp=tx.timestamp,
            tx_id=tx.tx_id,
            block_index=block_index,
            perceptual_hash=tx.perceptual_hash,
            derived_from=tx.derived_from,
        )
    elif tx.tx_type == REVOKE:
        if existing is None:
            raise ValidationError(f"content {tx.content_hash} is not registered")
        if existing.revoked:
            raise ValidationError(f"content {tx.content_hash} is already revoked")
        if existing.owner != tx.owner:
            raise ValidationError("only the owner can revoke a proof")
        registry[tx.content_hash] = replace(existing, revoked=True, revoked_at=tx.timestamp, revoke_tx_id=tx.tx_id)
    elif tx.tx_type == DISPUTE:
        if existing is None or existing.revoked:
            raise ValidationError(f"content {tx.content_hash} has no active registration to dispute")
        if existing.owner == tx.owner:
            raise ValidationError("you cannot dispute your own proof")
        if any(dispute.disputer == tx.owner for dispute in existing.disputes):
            raise ValidationError("you have already disputed this proof")
        evidence_timestamp = None
        if tx.evidence is not None:
            evidence = registry.get(tx.evidence)
            if evidence is None or evidence.owner != tx.owner:
                raise ValidationError("evidence must be one of your own registrations")
            evidence_timestamp = evidence.timestamp
        dispute = DisputeRecord(
            disputer=tx.owner,
            reason=tx.metadata["reason"],
            timestamp=tx.timestamp,
            tx_id=tx.tx_id,
            block_index=block_index,
            evidence=tx.evidence,
            evidence_timestamp=evidence_timestamp,
        )
        registry[tx.content_hash] = replace(existing, disputes=existing.disputes + (dispute,))
    else:
        raise ValidationError(f"unknown tx_type: {tx.tx_type!r}")


class Blockchain():
    def __init__(self, difficulty: int = DEFAULT_DIFFICULTY, storage_path=None):
        self.difficulty = difficulty
        self.storage_path = Path(storage_path) if storage_path else None
        self._lock = threading.RLock()
        self.blocks: list[Block] = [Block.genesis()]
        self.state = LedgerState()
        self.mempool: dict[str, Transaction] = {}
        self._tx_ids: set[str] = set()
        if self.storage_path and self.storage_path.exists():
            self.load()

    @property
    def tip(self) -> Block:
        return self.blocks[-1]

    @property
    def height(self) -> int:
        return len(self.blocks)

    @property
    def registry(self) -> dict[str, ProofRecord]:
        return self.state.registry

    # ---------------------------------------------------------------- mempool

    def add_transaction(self, tx: Transaction) -> bool:
        # returns False if the transaction is already known, raises if invalid
        with self._lock:
            if tx.tx_id in self.mempool or tx.tx_id in self._tx_ids:
                return False
            tx.validate()
            apply_transaction(self._pending_state(), tx, PENDING)
            self.mempool[tx.tx_id] = tx
            return True

    def _pending_state(self) -> LedgerState:
        state = self.state.copy()
        for pending in self.mempool.values():
            apply_transaction(state, pending, PENDING)
        return state

    def _rebuild_mempool(self, candidates: list[Transaction]) -> None:
        # keeps only candidates that are still valid on top of the current chain
        self.mempool = {}
        state = self.state.copy()
        for tx in candidates:
            if tx.tx_id in self._tx_ids or tx.tx_id in self.mempool:
                continue
            try:
                apply_transaction(state, tx, PENDING)
            except ValidationError:
                continue
            self.mempool[tx.tx_id] = tx

    # ----------------------------------------------------------------- mining

    def build_block(self, miner: str) -> Block:
        with self._lock:
            return Block(
                index=self.height,
                timestamp=max(now_ms(), self.tip.timestamp),
                prev_hash=self.tip.hash,
                difficulty=self.difficulty,
                miner=miner,
                transactions=list(self.mempool.values())[:MAX_TXS_PER_BLOCK],
            )

    def mine_pending(self, miner: str, allow_empty: bool = False, stop_event: threading.Event | None = None) -> Block | None:
        # proof-of-work runs outside the lock so the node keeps serving requests;
        # if the tip moved meanwhile, add_block rejects the stale block
        block = self.build_block(miner)
        if not block.transactions and not allow_empty:
            return None
        if not block.mine(stop_event):
            return None
        self.add_block(block)
        return block

    # ------------------------------------------------------------- validation

    def _validate_block(self, block: Block, prev: Block, base: LedgerState, seen_tx_ids: set) -> tuple[LedgerState, set]:
        if block.index != prev.index + 1:
            raise ValidationError(f"expected block index {prev.index + 1}, got {block.index}")
        if block.prev_hash != prev.hash:
            raise ValidationError(f"block #{block.index} does not link to the previous block")
        if block.difficulty != self.difficulty:
            raise ValidationError(f"block #{block.index} has difficulty {block.difficulty}, chain requires {self.difficulty}")
        if not isinstance(block.miner, str) or len(block.miner) > MAX_MINER_LENGTH:
            raise ValidationError(f"block #{block.index} has an invalid miner field")
        if block.merkle_root != merkle_root([tx.tx_id for tx in block.transactions]):
            raise ValidationError(f"block #{block.index} merkle root does not match its transactions")
        if block.hash != block.compute_hash():
            raise ValidationError(f"block #{block.index} hash does not match its contents")
        if not block.meets_difficulty():
            raise ValidationError(f"block #{block.index} does not satisfy proof-of-work")
        if block.timestamp < prev.timestamp or block.timestamp > now_ms() + MAX_FUTURE_DRIFT_MS:
            raise ValidationError(f"block #{block.index} has an invalid timestamp")
        if len(block.transactions) > MAX_TXS_PER_BLOCK:
            raise ValidationError(f"block #{block.index} has too many transactions")

        state = base.copy()
        block_tx_ids = set()
        for tx in block.transactions:
            tx.validate()
            if tx.tx_id in seen_tx_ids or tx.tx_id in block_tx_ids:
                raise ValidationError(f"duplicate transaction {tx.tx_id}")
            block_tx_ids.add(tx.tx_id)
            apply_transaction(state, tx, block.index)
        return state, block_tx_ids

    def _replay(self, blocks: list[Block]) -> tuple[LedgerState, set]:
        # validates a whole chain from genesis and returns its derived state
        if not blocks or blocks[0].to_dict() != Block.genesis().to_dict():
            raise ValidationError("chain does not start with the ProofChain genesis block")
        state, tx_ids = LedgerState(), set()
        for prev, block in zip(blocks, blocks[1:]):
            state, block_tx_ids = self._validate_block(block, prev, state, tx_ids)
            tx_ids |= block_tx_ids
        return state, tx_ids

    def is_valid(self) -> bool:
        with self._lock:
            try:
                self._replay(self.blocks)
                return True
            except ValidationError:
                return False

    # -------------------------------------------------------------- consensus

    def add_block(self, block: Block) -> None:
        with self._lock:
            self.state, block_tx_ids = self._validate_block(block, self.tip, self.state, self._tx_ids)
            self.blocks.append(block)
            self._tx_ids |= block_tx_ids
            self._rebuild_mempool(list(self.mempool.values()))
            self.save()

    def replace_chain(self, blocks: list[Block]) -> bool:
        # longest valid chain wins (all blocks share one difficulty, so length == work)
        with self._lock:
            if len(blocks) <= self.height:
                return False
            try:
                state, tx_ids = self._replay(blocks)
            except ValidationError:
                return False
            # transactions from our abandoned blocks go back to the mempool
            orphaned = [tx for block in self.blocks[1:] for tx in block.transactions if tx.tx_id not in tx_ids]
            self.blocks, self.state, self._tx_ids = list(blocks), state, tx_ids
            self._rebuild_mempool(orphaned + list(self.mempool.values()))
            self.save()
            return True

    # ---------------------------------------------------------------- queries

    def lookup(self, content_hash: str) -> tuple[str, ProofRecord] | None:
        # returns (status, record): confirmed | revoked for on-chain records,
        # pending for registrations still waiting in the mempool
        content_hash = content_hash.lower()
        if not is_hex_digest(content_hash):
            return None
        with self._lock:
            record = self.registry.get(content_hash)
            if record is not None:
                return ("revoked" if record.revoked else "confirmed"), record
            pending = self._pending_state().registry.get(content_hash)
        if pending is not None:
            return "pending", pending
        return None

    def proofs_by_owner(self, address: str) -> list[ProofRecord]:
        with self._lock:
            return [record for record in self.registry.values() if record.owner == address]

    def identity(self, address: str) -> IdentityRecord | None:
        with self._lock:
            return self.state.identities.get(address)

    def similar(self, perceptual_hash: str, max_distance: int = 10) -> list[tuple[int, ProofRecord]]:
        # registrations whose image dHash is within `max_distance` bits, closest first
        with self._lock:
            candidates = [record for record in self.registry.values() if record.perceptual_hash]
        matches = [(hamming_distance(perceptual_hash, record.perceptual_hash), record) for record in candidates]
        return sorted(((d, r) for d, r in matches if d <= max_distance), key=lambda item: (item[0], item[1].timestamp))

    # ------------------------------------------------------------ persistence

    def to_dict(self) -> dict:
        with self._lock:
            return {
                "difficulty": self.difficulty,
                "length": self.height,
                "blocks": [block.to_dict() for block in self.blocks],
            }

    def save(self) -> None:
        if not self.storage_path:
            return
        self.storage_path.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = self.storage_path.with_suffix(self.storage_path.suffix + ".tmp")
        tmp_path.write_text(json.dumps(self.to_dict(), indent=1), encoding="utf-8")
        os.replace(tmp_path, self.storage_path)  # atomic: never leaves a half-written chain

    def load(self) -> None:
        # stored data is re-validated from genesis, never trusted blindly
        data = json.loads(self.storage_path.read_text(encoding="utf-8"))
        blocks = [Block.from_dict(block) for block in data["blocks"]]
        with self._lock:
            self.state, self._tx_ids = self._replay(blocks)
            self.blocks = blocks
            self.mempool = {}
