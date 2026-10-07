##################################################
# author:   mrbacco <mrbacco04@gmail.com>
# date:     2026-10-07
# filename: proofchain/transaction.py
#
# signed transactions:
#   register -> anchor a content hash to its owner
#               (optionally derived_from an earlier
#               original, with a perceptual hash)
#   revoke   -> the owner withdraws a proof
#   dispute  -> someone else challenges a proof,
#               optionally citing their own earlier
#               registration as evidence
#   identity -> attach a name (and a domain that
#               can vouch for it) to an address
##################################################

import re
from dataclasses import dataclass, field

from proofchain.utils import ValidationError, canonical_json, is_hex_digest, now_ms, sha3_hex
from proofchain.wallet import Wallet, address_from_public_key, verify_signature

REGISTER = "register"
REVOKE = "revoke"
DISPUTE = "dispute"
IDENTITY = "identity"
TX_TYPES = (REGISTER, REVOKE, DISPUTE, IDENTITY)

MAX_METADATA_BYTES = 2048
MAX_METADATA_KEY_LENGTH = 64
MAX_NAME_LENGTH = 100
MAX_REASON_LENGTH = 1000

_PERCEPTUAL_HASH = re.compile(r"^[0-9a-f]{16}$")
# hostname with an optional port, e.g. example.com or localhost:8000
_DOMAIN = re.compile(r"^(?=.{1,253}(:|$))([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*(:\d{1,5})?$")

# optional fields: part of the signed payload only when set, so transactions
# created before they existed keep exactly the same bytes, signature and id
OPTIONAL_FIELDS = {
    "perceptual_hash": (REGISTER,),
    "derived_from": (REGISTER,),
    "evidence": (DISPUTE,),
}


def is_domain(value) -> bool:
    return isinstance(value, str) and bool(_DOMAIN.match(value))


@dataclass
class Transaction():
    tx_type: str
    content_hash: str
    public_key: str
    timestamp: int
    metadata: dict = field(default_factory=dict)
    signature: str = ""
    perceptual_hash: str | None = None
    derived_from: str | None = None
    evidence: str | None = None

    @classmethod
    def create(cls, wallet: Wallet, tx_type: str, content_hash: str = "", metadata: dict | None = None, **optional) -> "Transaction":
        tx = cls(
            tx_type=tx_type,
            content_hash=content_hash.lower(),
            public_key=wallet.public_key_hex,
            timestamp=now_ms(),
            metadata=dict(metadata or {}),
            **{key: value.lower() for key, value in optional.items() if value},
        )
        tx.signature = wallet.sign(tx.signing_bytes())
        return tx

    @classmethod
    def identity(cls, wallet: Wallet, name: str, domain: str | None = None) -> "Transaction":
        metadata = {"name": name.strip()}
        if domain:
            metadata["domain"] = domain.strip().lower()
        return cls.create(wallet, IDENTITY, "", metadata)

    def payload(self) -> dict:
        # everything that is signed (the signature itself is not)
        payload = {
            "tx_type": self.tx_type,
            "content_hash": self.content_hash,
            "public_key": self.public_key,
            "timestamp": self.timestamp,
            "metadata": self.metadata,
        }
        for name in OPTIONAL_FIELDS:
            if getattr(self, name) is not None:
                payload[name] = getattr(self, name)
        return payload

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
        if self.tx_type == IDENTITY:
            if self.content_hash != "":
                raise ValidationError("identity transactions must have an empty content_hash")
        elif not is_hex_digest(self.content_hash):
            raise ValidationError("content_hash must be a lowercase 64-char sha3-256 hex digest")
        if not isinstance(self.public_key, str) or len(self.public_key) != 66:
            raise ValidationError("public_key must be a compressed secp256k1 point (66 hex chars)")
        if not isinstance(self.timestamp, int) or isinstance(self.timestamp, bool) or self.timestamp <= 0:
            raise ValidationError("timestamp must be a positive integer (ms)")
        self._validate_metadata()
        self._validate_optional_fields()
        self._validate_type_rules()
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

    def _validate_optional_fields(self) -> None:
        for name, allowed_types in OPTIONAL_FIELDS.items():
            value = getattr(self, name)
            if value is None:
                continue
            if self.tx_type not in allowed_types:
                raise ValidationError(f"{name} is not allowed on {self.tx_type} transactions")
            if name == "perceptual_hash":
                if not isinstance(value, str) or not _PERCEPTUAL_HASH.match(value):
                    raise ValidationError("perceptual_hash must be 16 lowercase hex chars (64-bit dHash)")
            elif not is_hex_digest(value):
                raise ValidationError(f"{name} must be a lowercase 64-char sha3-256 hex digest")
        if self.derived_from is not None and self.derived_from == self.content_hash:
            raise ValidationError("a file cannot be derived from itself")
        if self.evidence is not None and self.evidence == self.content_hash:
            raise ValidationError("the disputed proof cannot be its own evidence")

    def _validate_type_rules(self) -> None:
        if self.tx_type == IDENTITY:
            name = self.metadata.get("name", "")
            if not name or len(name) > MAX_NAME_LENGTH or name != name.strip():
                raise ValidationError(f"identity needs a name of 1-{MAX_NAME_LENGTH} characters")
            if "domain" in self.metadata and not is_domain(self.metadata["domain"]):
                raise ValidationError("identity domain must be a lowercase hostname, e.g. example.com")
            if set(self.metadata) - {"name", "domain"}:
                raise ValidationError("identity metadata only accepts name and domain")
        elif self.tx_type == DISPUTE:
            reason = self.metadata.get("reason", "")
            if not reason.strip() or len(reason) > MAX_REASON_LENGTH:
                raise ValidationError(f"a dispute needs a reason of 1-{MAX_REASON_LENGTH} characters")

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
                **{name: data[name] for name in OPTIONAL_FIELDS if data.get(name) is not None},
            )
        except (KeyError, TypeError) as exc:
            raise ValidationError(f"malformed transaction: {exc}") from exc

    def __str__(self):
        target = self.content_hash[:16] + "..." if self.content_hash else self.metadata.get("name", "")
        return f"{self.tx_type} {target} by {self.owner} ({self.tx_id[:12]})"
