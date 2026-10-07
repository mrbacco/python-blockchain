##################################################
# author:   mrbacco <mrbacco04@gmail.com>
# date:     2026-10-07
# filename: tests/test_chain.py
#
# tests for wallet, transactions, blocks, chain
# rules, consensus and persistence
##################################################

import pytest

from proofchain.block import Block
from proofchain.chain import Blockchain
from proofchain.transaction import REGISTER, REVOKE, Transaction
from proofchain.utils import ValidationError, sha3_hex
from proofchain.wallet import Wallet

DIFFICULTY = 2


def content(name: str) -> str:
    return sha3_hex(name.encode())


@pytest.fixture
def alice():
    return Wallet()


@pytest.fixture
def bob():
    return Wallet()


@pytest.fixture
def chain():
    return Blockchain(difficulty=DIFFICULTY)


def register(chain, wallet, name, **metadata):
    tx = Transaction.create(wallet, REGISTER, content(name), metadata)
    chain.add_transaction(tx)
    return tx


# ------------------------------------------------------------------ wallet

def test_wallet_roundtrip_with_password(tmp_path, alice):
    path = tmp_path / "w.pem"
    alice.save(path, password="secret")
    loaded = Wallet.load(path, password="secret")
    assert loaded.address == alice.address
    with pytest.raises(FileExistsError):
        alice.save(path)


# ------------------------------------------------------------ transactions

def test_transaction_signature_and_tamper(alice):
    tx = Transaction.create(alice, REGISTER, content("photo"), {"title": "sunset"})
    tx.validate()
    clone = Transaction.from_dict(tx.to_dict())
    assert clone.tx_id == tx.tx_id
    clone.metadata["title"] = "forged"
    with pytest.raises(ValidationError, match="signature"):
        clone.validate()


def test_transaction_rejects_bad_fields(alice):
    with pytest.raises(ValidationError, match="content_hash"):
        Transaction.create(alice, REGISTER, "not-a-hash").validate()
    with pytest.raises(ValidationError, match="metadata"):
        Transaction.create(alice, REGISTER, content("x"), {"n": 1}).validate()
    with pytest.raises(ValidationError, match="malformed"):
        Transaction.from_dict({"tx_type": REGISTER})


# ------------------------------------------------------------- chain rules

def test_register_mine_and_lookup(chain, alice):
    register(chain, alice, "photo", title="sunset")
    assert chain.lookup(content("photo"))[0] == "pending"
    block = chain.mine_pending(alice.address)
    assert block.index == 1 and block.hash.startswith("0" * DIFFICULTY)
    status, record = chain.lookup(content("photo"))
    assert status == "confirmed"
    assert record.owner == alice.address and record.block_index == 1
    assert chain.proofs_by_owner(alice.address) == [record]
    assert chain.is_valid()


def test_mine_without_transactions_returns_none(chain, alice):
    assert chain.mine_pending(alice.address) is None


def test_duplicate_registration_rejected(chain, alice, bob):
    register(chain, alice, "photo")
    with pytest.raises(ValidationError, match="already registered"):
        register(chain, bob, "photo")  # rejected while still pending
    chain.mine_pending("m")
    with pytest.raises(ValidationError, match="already registered"):
        register(chain, bob, "photo")  # and once confirmed


def test_replayed_transaction_is_ignored(chain, alice):
    tx = register(chain, alice, "photo")
    chain.mine_pending("m")
    assert chain.add_transaction(Transaction.from_dict(tx.to_dict())) is False


def test_only_owner_can_revoke(chain, alice, bob):
    register(chain, alice, "photo")
    chain.mine_pending("m")
    with pytest.raises(ValidationError, match="owner"):
        chain.add_transaction(Transaction.create(bob, REVOKE, content("photo")))
    chain.add_transaction(Transaction.create(alice, REVOKE, content("photo")))
    chain.mine_pending("m")
    status, record = chain.lookup(content("photo"))
    assert status == "revoked" and record.revoked_at is not None
    register(chain, bob, "photo")  # a revoked hash can be claimed again


def test_tampering_breaks_validation(chain, alice):
    register(chain, alice, "photo")
    chain.mine_pending("m")
    register(chain, alice, "video")
    chain.mine_pending("m")
    chain.blocks[1].transactions[0].metadata["title"] = "forged"
    assert not chain.is_valid()


def test_block_with_bad_pow_or_link_rejected(chain, alice):
    register(chain, alice, "photo")
    block = chain.build_block("m")
    block.nonce, block.hash = 0, block.compute_hash()
    while block.meets_difficulty():  # make sure the pow is actually invalid
        block.nonce += 1
        block.hash = block.compute_hash()
    with pytest.raises(ValidationError, match="proof-of-work"):
        chain.add_block(block)
    block.prev_hash = "f" * 64
    block.mine()
    with pytest.raises(ValidationError, match="link"):
        chain.add_block(block)


def test_block_with_wrong_difficulty_rejected(chain, alice):
    register(chain, alice, "photo")
    block = chain.build_block("m")
    block.difficulty = 1
    block.mine()
    with pytest.raises(ValidationError, match="difficulty"):
        chain.add_block(block)


# --------------------------------------------------------------- consensus

def test_longest_valid_chain_wins_and_orphans_return(alice, bob):
    a, b = Blockchain(DIFFICULTY), Blockchain(DIFFICULTY)
    register(a, alice, "only-on-a")
    a.mine_pending("a")
    register(b, bob, "b1")
    b.mine_pending("b")
    register(b, bob, "b2")
    b.mine_pending("b")

    assert a.replace_chain(b.blocks) is True
    assert a.height == 3 and a.tip.hash == b.tip.hash
    # alice's proof from the abandoned fork is back in the mempool
    assert a.lookup(content("only-on-a"))[0] == "pending"
    assert b.replace_chain(a.blocks) is False  # not longer


def test_invalid_longer_chain_is_refused(alice):
    a, b = Blockchain(DIFFICULTY), Blockchain(DIFFICULTY)
    for name in ("x", "y"):
        register(b, alice, name)
        b.mine_pending("b")
    forged = [Block.from_dict(block.to_dict()) for block in b.blocks]
    forged[2].transactions[0].metadata["title"] = "forged"
    assert a.replace_chain(forged) is False
    assert a.height == 1


# ------------------------------------------------------------- persistence

def test_persistence_reloads_and_revalidates(tmp_path, alice):
    path = tmp_path / "chain.json"
    chain = Blockchain(DIFFICULTY, path)
    register(chain, alice, "photo")
    chain.mine_pending("m")

    reloaded = Blockchain(DIFFICULTY, path)
    assert reloaded.height == 2
    assert reloaded.lookup(content("photo"))[0] == "confirmed"

    path.write_text(path.read_text().replace(content("photo"), content("forged")))
    with pytest.raises(ValidationError):
        Blockchain(DIFFICULTY, path)
