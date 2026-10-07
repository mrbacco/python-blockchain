##################################################
# author:   mrbacco <mrbacco04@gmail.com>
# date:     2026-10-07
# filename: proofchain/api.py
#
# REST API of a node (FastAPI): used by peers
# for gossip, by the CLI, and later by the web
# app (CORS is enabled for that purpose)
##################################################

from fastapi import BackgroundTasks, Body, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from proofchain import __version__
from proofchain.node import Node
from proofchain.transaction import Transaction
from proofchain.utils import ValidationError


class PeersIn(BaseModel):
    peers: list[str]


def create_app(node: Node) -> FastAPI:
    chain = node.chain
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
        status, record = found
        return {"status": status, **record.to_dict()}

    @app.get("/owners/{address}/proofs")
    def get_owner_proofs(address: str):
        return {"address": address, "proofs": [record.to_dict() for record in chain.proofs_by_owner(address)]}

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

    return app
