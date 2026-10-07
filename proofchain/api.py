##################################################
# author:   mrbacco <mrbacco04@gmail.com>
# date:     2026-10-07
# filename: proofchain/api.py
#
# REST API of a node (FastAPI): used by peers
# for gossip, by the CLI, and later by the web
# app (CORS is enabled for that purpose); also
# serves the browser UI from proofchain/web at /ui
##################################################

from pathlib import Path

from fastapi import BackgroundTasks, Body, FastAPI, HTTPException, Query
from fastapi import Path as Path_
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from proofchain import __version__
from proofchain.identity import DomainVerifier
from proofchain.node import Node
from proofchain.perceptual import SIMILAR_DISTANCE
from proofchain.transaction import Transaction
from proofchain.utils import ValidationError

WEB_DIR = Path(__file__).parent / "web"
PERCEPTUAL_HASH_PATTERN = r"^[0-9a-fA-F]{16}$"


class PeersIn(BaseModel):
    peers: list[str]


def create_app(node: Node, verifier: DomainVerifier | None = None) -> FastAPI:
    chain = node.chain
    verifier = verifier or DomainVerifier()

    def describe_identity(address: str) -> dict | None:
        # on-chain identity plus a live (cached) check of its domain
        identity = chain.identity(address)
        if identity is None:
            return None
        check = verifier.check(identity.domain, address).to_dict() if identity.domain else None
        return {**identity.to_dict(), "domain_check": check}

    def describe_proof(status: str, record) -> dict:
        data = {"status": status, **record.to_dict(), "owner_identity": describe_identity(record.owner)}
        for dispute in data["disputes"]:
            dispute["disputer_identity"] = describe_identity(dispute["disputer"])
        if record.derived_from:
            original = chain.lookup(record.derived_from)
            data["derived_from_record"] = (
                {"status": original[0], "timestamp": original[1].timestamp, "metadata": original[1].metadata}
                if original else None
            )
        return data
    app = FastAPI(title="ProofChain node", version=__version__)
    app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

    @app.get("/")
    def info():
        return {
            "name": "ProofChain",
            "version": __version__,
            "height": chain.height,
            "tip": chain.tip.hash,
            "difficulty": chain.difficulty,
            "pending": len(chain.mempool),
            "peers": sorted(node.peers),
        }

    @app.get("/chain")
    def get_chain():
        return chain.to_dict()

    @app.get("/blocks/{index}")
    def get_block(index: int):
        if not 0 <= index < chain.height:
            raise HTTPException(404, "block not found")
        return chain.blocks[index].to_dict()

    @app.get("/mempool")
    def get_mempool():
        return {"transactions": [tx.to_dict() for tx in list(chain.mempool.values())]}

    @app.post("/transactions", status_code=201)
    def post_transaction(background: BackgroundTasks, payload: dict = Body(...)):
        try:
            tx = Transaction.from_dict(payload)
            added = chain.add_transaction(tx)
        except ValidationError as exc:
            raise HTTPException(400, str(exc)) from exc
        if added:
            background.add_task(node.broadcast_transaction, tx)
        return {"tx_id": tx.tx_id, "status": "pending" if added else "known"}

    @app.post("/mine")
    def mine():
        try:
            block = node.mine()
        except ValidationError as exc:
            # the tip moved while mining (a peer block arrived first)
            raise HTTPException(409, f"block went stale: {exc}") from exc
        if block is None:
            return {"mined": False, "message": "no pending transactions"}
        return {"mined": True, "block": block.to_dict()}

    @app.post("/blocks")
    def post_block(background: BackgroundTasks, payload: dict = Body(...)):
        try:
            status = node.receive_block(payload)
        except ValidationError as exc:
            raise HTTPException(400, str(exc)) from exc
        if status == "added":
            background.add_task(node.broadcast_block, chain.tip)
        return {"status": status, "height": chain.height}

    @app.get("/proofs/{content_hash}")
    def get_proof(content_hash: str):
        found = chain.lookup(content_hash)
        if found is None:
            raise HTTPException(404, "no proof registered for this content hash")
        return describe_proof(*found)

    @app.get("/similar/{perceptual_hash}")
    def get_similar(perceptual_hash: str = Path_(pattern=PERCEPTUAL_HASH_PATTERN),
                    max_distance: int = Query(SIMILAR_DISTANCE, ge=0, le=32)):
        # registered images that look like the given one (resized, re-encoded, lightly edited)
        matches = chain.similar(perceptual_hash.lower(), max_distance)
        return {"matches": [
            {"distance": distance, **describe_proof("revoked" if record.revoked else "confirmed", record)}
            for distance, record in matches
        ]}

    @app.get("/owners/{address}/proofs")
    def get_owner_proofs(address: str):
        return {
            "address": address,
            "identity": describe_identity(address),
            "proofs": [record.to_dict() for record in chain.proofs_by_owner(address)],
        }

    @app.get("/identities/{address}")
    def get_identity(address: str):
        identity = describe_identity(address)
        if identity is None:
            raise HTTPException(404, "this address has not published an identity")
        return identity

    @app.get("/peers")
    def get_peers():
        return {"peers": sorted(node.peers)}

    @app.post("/peers")
    def post_peers(body: PeersIn):
        return {"added": node.add_peers(body.peers), "peers": sorted(node.peers)}

    @app.post("/consensus")
    def consensus():
        replaced = node.resolve_conflicts()
        return {"replaced": replaced, "height": chain.height, "tip": chain.tip.hash}

    @app.get("/validate")
    def validate():
        return {"valid": chain.is_valid(), "height": chain.height}

    @app.get("/ui", include_in_schema=False)
    def ui_redirect():
        return RedirectResponse("/ui/")

    app.mount("/ui", StaticFiles(directory=WEB_DIR, html=True), name="ui")

    return app
