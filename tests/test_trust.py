##################################################
# author:   mrbacco <mrbacco04@gmail.com>
# date:     2026-10-07
# filename: tests/test_trust.py
#
# tests for the trust features: identities with
# domain verification, disputes, derived_from
# provenance and perceptual (similar image) search
##################################################

import pytest
from fastapi.testclient import TestClient

from proofchain.api import create_app
from proofchain.chain import Blockchain
from proofchain.identity import DomainVerifier
from proofchain.node import Node
from proofchain.perceptual import dhash_from_grid, hamming_distance, image_dhash
from proofchain.transaction import DISPUTE, REGISTER, Transaction
from proofchain.utils import ValidationError, sha3_hex
from proofchain.wallet import Wallet

DIFFICULTY = 1


def h(name: str) -> str:
    return sha3_hex(name.encode())


@pytest.fixture
def chain():
    return Blockchain(difficulty=DIFFICULTY)


@pytest.fixture
def alice():
    return Wallet()


@pytest.fixture
def mallory():
    return Wallet()


def submit(chain, tx, mine=True):
    chain.add_transaction(tx)
    if mine:
        chain.mine_pending("m")
    return tx


# ---------------------------------------------------------------- identity

def test_identity_set_and_update(chain, alice):
    submit(chain, Transaction.identity(alice, "Alice Rossi", "alice.example"))
    assert chain.identity(alice.address).name == "Alice Rossi"
    submit(chain, Transaction.identity(alice, "Alice R.", "alice.example"))
    assert chain.identity(alice.address).name == "Alice R."


@pytest.mark.parametrize("name, domain, error", [
    ("", None, "name"),
    (" padded ", None, "name"),
    ("ok", "not a domain", "domain"),
    ("ok", "https://example.com", "domain"),
])
def test_identity_rejects_bad_fields(alice, name, domain, error):
    tx = Transaction.create(alice, "identity", "", {"name": name, **({"domain": domain} if domain else {})})
    with pytest.raises(ValidationError, match=error):
        tx.validate()


def test_identity_needs_empty_content_hash(alice):
    with pytest.raises(ValidationError, match="empty content_hash"):
        Transaction.create(alice, "identity", h("x"), {"name": "A"}).validate()


class StubVerifier(DomainVerifier):
    def __init__(self, documents):
        super().__init__()
        self.documents = documents

    def _fetch(self, domain):
        if domain not in self.documents:
            return None, f"could not fetch {domain}"
        return set(self.documents[domain]), "ok"


def test_domain_verification_through_api(alice, mallory):
    node = Node(Blockchain(DIFFICULTY))
    client = TestClient(create_app(node, StubVerifier({"alice.example": [alice.address]})))
    for wallet, name in ((alice, "Alice"), (mallory, "Alice")):  # mallory impersonates the name...
        client.post("/transactions", json=Transaction.identity(wallet, name, "alice.example").to_dict())
    client.post("/mine")

    real = client.get(f"/identities/{alice.address}").json()
    fake = client.get(f"/identities/{mallory.address}").json()
    assert real["domain_check"]["verified"] is True
    assert fake["domain_check"]["verified"] is False  # ...but the domain does not list her
    assert "not listed" in fake["domain_check"]["detail"]
    assert client.get(f"/identities/{Wallet().address}").status_code == 404


def test_verifier_refuses_private_hosts():
    verifier = DomainVerifier()
    for domain in ("localhost", "127.0.0.1", "example.com:8080", "bad domain"):
        assert verifier.check(domain, "pc00").verified is False


# ---------------------------------------------------------------- disputes

def test_dispute_with_earlier_evidence(chain, alice, mallory):
    # alice registered her unpublished RAW first; mallory claims the published JPEG first
    submit(chain, Transaction.create(alice, REGISTER, h("raw")))
    submit(chain, Transaction.create(mallory, REGISTER, h("jpeg")))
    submit(chain, Transaction.create(alice, DISPUTE, h("jpeg"), {"reason": "this is my photo"}, evidence=h("raw")))

    status, record = chain.lookup(h("jpeg"))
    assert status == "confirmed" and record.owner == mallory.address
    [dispute] = record.disputes
    assert dispute.disputer == alice.address and dispute.evidence == h("raw")
    assert dispute.evidence_timestamp < record.timestamp  # alice's evidence predates mallory's claim


def test_dispute_rules(chain, alice, mallory):
    submit(chain, Transaction.create(alice, REGISTER, h("doc")))
    with pytest.raises(ValidationError, match="your own proof"):
        chain.add_transaction(Transaction.create(alice, DISPUTE, h("doc"), {"reason": "x"}))
    with pytest.raises(ValidationError, match="no active registration"):
        chain.add_transaction(Transaction.create(mallory, DISPUTE, h("nothing"), {"reason": "x"}))
    with pytest.raises(ValidationError, match="evidence must be one of your own"):
        chain.add_transaction(Transaction.create(mallory, DISPUTE, h("doc"), {"reason": "x"}, evidence=h("doc2")))
    with pytest.raises(ValidationError, match="reason"):
        Transaction.create(mallory, DISPUTE, h("doc"), {"reason": "  "}).validate()
    submit(chain, Transaction.create(mallory, DISPUTE, h("doc"), {"reason": "fake"}))
    with pytest.raises(ValidationError, match="already disputed"):
        chain.add_transaction(Transaction.create(mallory, DISPUTE, h("doc"), {"reason": "again"}))


# ------------------------------------------------------------ derived_from

def test_derived_from_must_be_own_registration(chain, alice, mallory):
    submit(chain, Transaction.create(alice, REGISTER, h("raw")))
    submit(chain, Transaction.create(alice, REGISTER, h("jpeg"), derived_from=h("raw")))
    assert chain.lookup(h("jpeg"))[1].derived_from == h("raw")
    with pytest.raises(ValidationError, match="your own registrations"):
        chain.add_transaction(Transaction.create(mallory, REGISTER, h("copy"), derived_from=h("raw")))
    with pytest.raises(ValidationError, match="not an active registration"):
        chain.add_transaction(Transaction.create(alice, REGISTER, h("x"), derived_from=h("missing")))


def test_optional_fields_only_on_their_types(alice):
    with pytest.raises(ValidationError, match="not allowed"):
        Transaction.create(alice, DISPUTE, h("a"), {"reason": "r"}, perceptual_hash="0" * 16).validate()
    with pytest.raises(ValidationError, match="perceptual_hash"):
        Transaction.create(alice, REGISTER, h("a"), perceptual_hash="xyz").validate()


def test_old_transactions_keep_their_id(alice):
    # optional fields are omitted when unset, so pre-existing transactions are unchanged
    tx = Transaction.create(alice, REGISTER, h("a"), {"title": "t"})
    assert set(tx.payload()) == {"tx_type", "content_hash", "public_key", "timestamp", "metadata"}


# --------------------------------------------------------------- perceptual

def test_dhash_basics():
    gradient = [[float(x) for x in range(9)] for _ in range(8)]  # brighter to the right
    assert dhash_from_grid(gradient) == "0" * 16
    assert dhash_from_grid([row[::-1] for row in gradient]) == "f" * 16
    assert hamming_distance("00ff", "00fe") == 1


def test_image_dhash_survives_resize_and_reencode(tmp_path):
    Image = pytest.importorskip("PIL.Image")
    image = Image.new("RGB", (400, 300))
    for x in range(400):
        for y in range(300):
            image.putpixel((x, y), ((x * 7) % 256, (y * 3) % 256, ((x + y) * 2) % 256))
    original, smaller = tmp_path / "a.png", tmp_path / "b.jpg"
    image.save(original)
    image.resize((200, 150)).save(smaller, quality=70)
    a, b = image_dhash(original), image_dhash(smaller)
    assert a and b and hamming_distance(a, b) <= 6
    assert image_dhash(tmp_path / "missing.png") is None
    (tmp_path / "notes.txt").write_text("not an image")
    assert image_dhash(tmp_path / "notes.txt") is None


def test_similar_search(chain, alice):
    submit(chain, Transaction.create(alice, REGISTER, h("img1"), perceptual_hash="ffff0000ffff0000"))
    submit(chain, Transaction.create(alice, REGISTER, h("img2"), perceptual_hash="0000ffff0000ffff"))
    matches = chain.similar("ffff0000ffff0001")
    assert [(d, r.content_hash) for d, r in matches] == [(1, h("img1"))]

    client = TestClient(create_app(Node(chain), StubVerifier({})))
    body = client.get("/similar/ffff0000ffff0001").json()
    assert body["matches"][0]["distance"] == 1
    assert client.get("/similar/nothex").status_code == 422
