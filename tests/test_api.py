##################################################
# author:   mrbacco <mrbacco04@gmail.com>
# date:     2026-10-07
# filename: tests/test_api.py
#
# end-to-end tests of the node REST API
##################################################

from fastapi.testclient import TestClient

from proofchain.api import create_app
from proofchain.chain import Blockchain
from proofchain.node import Node
from proofchain.transaction import REGISTER, REVOKE, Transaction
from proofchain.utils import sha3_hex
from proofchain.wallet import Wallet


def make_client():
    node = Node(Blockchain(difficulty=2), miner="test-node")
    return TestClient(create_app(node)), node


def test_register_mine_verify_revoke_flow():
    client, _ = make_client()
    wallet = Wallet()
    content_hash = sha3_hex(b"my original photo")

    assert client.get(f"/proofs/{content_hash}").status_code == 404

    tx = Transaction.create(wallet, REGISTER, content_hash, {"title": "photo"})
    response = client.post("/transactions", json=tx.to_dict())
    assert response.status_code == 201 and response.json()["status"] == "pending"
    assert client.post("/transactions", json=tx.to_dict()).json()["status"] == "known"
    assert client.get(f"/proofs/{content_hash}").json()["status"] == "pending"

    mined = client.post("/mine").json()
    assert mined["mined"] is True and mined["block"]["index"] == 1
    assert client.post("/mine").json()["mined"] is False

    proof = client.get(f"/proofs/{content_hash}").json()
    assert proof["status"] == "confirmed" and proof["owner"] == wallet.address
    assert client.get(f"/owners/{wallet.address}/proofs").json()["proofs"][0]["content_hash"] == content_hash

    client.post("/transactions", json=Transaction.create(wallet, REVOKE, content_hash).to_dict())
    client.post("/mine")
    assert client.get(f"/proofs/{content_hash}").json()["status"] == "revoked"
    assert client.get("/validate").json() == {"valid": True, "height": 3}


def test_rejects_invalid_and_conflicting_transactions():
    client, _ = make_client()
    alice, mallory = Wallet(), Wallet()
    content_hash = sha3_hex(b"doc")

    forged = Transaction.create(alice, REGISTER, content_hash).to_dict()
    forged["metadata"] = {"title": "changed after signing"}
    assert client.post("/transactions", json=forged).status_code == 400
    assert client.post("/transactions", json={"foo": "bar"}).status_code == 400

    client.post("/transactions", json=Transaction.create(alice, REGISTER, content_hash).to_dict())
    response = client.post("/transactions", json=Transaction.create(mallory, REGISTER, content_hash).to_dict())
    assert response.status_code == 400 and "already registered" in response.json()["detail"]


def test_block_gossip_between_nodes():
    client_a, node_a = make_client()
    client_b, node_b = make_client()
    tx = Transaction.create(Wallet(), REGISTER, sha3_hex(b"shared"))
    client_a.post("/transactions", json=tx.to_dict())
    block = client_a.post("/mine").json()["block"]

    assert client_b.post("/blocks", json=block).json() == {"status": "added", "height": 2}
    assert client_b.post("/blocks", json=block).json()["status"] == "known"
    assert node_b.chain.tip.hash == node_a.chain.tip.hash

    tampered = dict(block, nonce=block["nonce"] + 1)
    assert client_b.post("/blocks", json=tampered).json()["status"] in ("known", "rejected")


def test_info_and_peers():
    client, _ = make_client()
    assert client.get("/").json()["height"] == 1
    assert client.post("/peers", json={"peers": ["127.0.0.1:5001/"]}).json()["peers"] == ["http://127.0.0.1:5001"]
    assert client.get("/blocks/0").json()["miner"] == "genesis"
    assert client.get("/blocks/9").status_code == 404
