##################################################
# author:   mrbacco <mrbacco04@gmail.com>
# date:     2026-10-07
# filename: proofchain/transaction.py
#
# signed transactions:
#   register -> anchor a content hash to its owner
#   revoke   -> the owner withdraws a proof
##################################################

from dataclasses import dataclass, field

from proofchain.utils import ValidationError, canonical_json, is_hex_digest, now_ms, sha3_hex
from proofchain.wallet import Wallet, address_from_public_key, verify_signature

REGISTER = "register"
REVOKE = "revoke"
TX_TYPES = (REGISTER, REVOKE)

MAX_METADATA_BYTES = 2048
MAX_METADATA_KEY_LENGTH = 64


@dataclass
class Transaction():
    tx_type: str
    content_hash: str
    public_key: str
    timestamp: int
    metadata: dict = field(default_factory=dict)
    signature: str = ""

    @classmethod
    def create(cls, wallet: Wallet, tx_type: str, content_hash: str, metadata: dict | None = None) -> "Transaction":
        tx = cls(
            tx_type=tx_type,
            content_hash=content_hash.lower(),
            public_key=wallet.public_key_hex,
            timestamp=now_ms(),
            metadata=dict(metadata or {}),
        )
        tx.signature = wallet.sign(tx.signing_bytes())
        return tx

    def payload(self) -> dict:
        # everything that is signed (the signature itself is not)
        return {
            "tx_type": self.tx_type,
            "content_hash": self.content_hash,
            "public_key": self.public_key,
            "timestamp": self.timestamp,
            "metadata": self.metadata,
        }

    def signing_bytes(self) -> bytes:
        return canonical_json(self.payload())

    @property
    def tx_id(self) -> str:
        # derived from the signed payload only, so re-encoding the
        # signature cannot produce a "different" transaction
        return sha3_hex(self.signing_bytes())

    @property
    def owner(self) -> str:
        return address_from_public_key(self.public_key)

    def validate(self) -> None:
        if self.tx_type not in TX_TYPES:
            raise ValidationError(f"unknown tx_type: {self.tx_type!r}")
        if not is_hex_digest(self.content_hash):
            raise ValidationError("content_hash must be a lowercase 64-char sha3-256 hex digest")
        if not isinstance(self.public_key, str) or len(self.public_key) != 66:
            raise ValidationError("public_key must be a compressed secp256k1 point (66 hex chars)")
        if not isinstance(self.timestamp, int) or isinstance(self.timestamp, bool) or self.timestamp <= 0:
            raise ValidationError("timestamp must be a positive integer (ms)")
        self._validate_metadata()
        if not isinstance(self.signature, str) or not verify_signature(self.public_key, self.signing_bytes(), self.signature):
            raise ValidationError("invalid signature")

    def _validate_metadata(self) -> None:
        if not isinstance(self.metadata, dict):
            raise ValidationError("metadata must be an object")
        for key, value in self.metadata.items():
            if not isinstance(key, str) or not key or len(key) > MAX_METADATA_KEY_LENGTH:
                raise ValidationError(f"invalid metadata key: {key!r}")
            if not isinstance(value, str):
                raise ValidationError(f"metadata value for {key!r} must be a string")
        if len(canonical_json(self.metadata)) > MAX_METADATA_BYTES:
            raise ValidationError(f"metadata exceeds {MAX_METADATA_BYTES} bytes")

    def to_dict(self) -> dict:
        return {**self.payload(), "signature": self.signature, "tx_id": self.tx_id}

    @classmethod
    def from_dict(cls, data: dict) -> "Transaction":
        try:
            return cls(
                tx_type=data["tx_type"],
                content_hash=data["content_hash"],
                public_key=data["public_key"],
                timestamp=data["timestamp"],
                metadata=data.get("metadata", {}),
                signature=data["signature"],
            )
        except (KeyError, TypeError) as exc:
            raise ValidationError(f"malformed transaction: {exc}") from exc

    def __str__(self):
        return f"{self.tx_type} {self.content_hash[:16]}... by {self.owner} ({self.tx_id[:12]})"
