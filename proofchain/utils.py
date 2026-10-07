##################################################
# author:   mrbacco <mrbacco04@gmail.com>
# date:     2026-10-07
# filename: proofchain/utils.py
#
# shared helpers: canonical serialization,
# hashing, timestamps and the validation error
##################################################

import hashlib
import json
import re
import time
from pathlib import Path

_HEX64 = re.compile(r"^[0-9a-f]{64}$")


class ValidationError(Exception):
    """raised whenever a transaction, block or chain breaks a consensus rule"""


def canonical_json(obj) -> bytes:
    # deterministic encoding used for every hash and signature;
    # matches JSON.stringify on sorted keys so a browser can reproduce it
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha3_hex(data: bytes) -> str:
    return hashlib.sha3_256(data).hexdigest()


def hash_file(path, chunk_size: int = 1 << 20) -> str:
    # streams the file so large media does not need to fit in memory
    digest = hashlib.sha3_256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(chunk_size), b""):
            digest.update(chunk)
    return digest.hexdigest()


def now_ms() -> int:
    # integer milliseconds: no float formatting differences between languages
    return int(time.time() * 1000)


def is_hex_digest(value) -> bool:
    return isinstance(value, str) and bool(_HEX64.match(value))
