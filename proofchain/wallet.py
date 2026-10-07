##################################################
# author:   mrbacco <mrbacco04@gmail.com>
# date:     2026-10-07
# filename: proofchain/wallet.py
#
# user-held keys: every creator owns a secp256k1
# key pair, signs their proofs with the private
# key and is identified by an address derived
# from the public key
##################################################

from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from proofchain.utils import sha3_hex

CURVE = ec.SECP256K1()
ADDRESS_PREFIX = "pc"


def address_from_public_key(public_key_hex: str) -> str:
    return ADDRESS_PREFIX + sha3_hex(bytes.fromhex(public_key_hex))[:40]


def verify_signature(public_key_hex: str, data: bytes, signature_hex: str) -> bool:
    try:
        public_key = ec.EllipticCurvePublicKey.from_encoded_point(CURVE, bytes.fromhex(public_key_hex))
        public_key.verify(bytes.fromhex(signature_hex), data, ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


class Wallet():
    def __init__(self, private_key: ec.EllipticCurvePrivateKey | None = None):
        self._private_key = private_key or ec.generate_private_key(CURVE)

    @property
    def public_key_hex(self) -> str:
        # compressed point (33 bytes -> 66 hex chars)
        return self._private_key.public_key().public_bytes(
            serialization.Encoding.X962,
            serialization.PublicFormat.CompressedPoint,
        ).hex()

    @property
    def address(self) -> str:
        return address_from_public_key(self.public_key_hex)

    def sign(self, data: bytes) -> str:
        return self._private_key.sign(data, ec.ECDSA(hashes.SHA256())).hex()

    def save(self, path, password: str | None = None, overwrite: bool = False) -> None:
        path = Path(path)
        if path.exists() and not overwrite:
            raise FileExistsError(f"wallet already exists: {path}")
        encryption = (
            serialization.BestAvailableEncryption(password.encode())
            if password else serialization.NoEncryption()
        )
        pem = self._private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            encryption,
        )
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(pem)

    @classmethod
    def load(cls, path, password: str | None = None) -> "Wallet":
        private_key = serialization.load_pem_private_key(
            Path(path).read_bytes(),
            password=password.encode() if password else None,
        )
        if not isinstance(private_key, ec.EllipticCurvePrivateKey) or private_key.curve.name != CURVE.name:
            raise ValueError("wallet file does not contain a secp256k1 key")
        return cls(private_key)
