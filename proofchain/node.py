##################################################
# author:   mrbacco <mrbacco04@gmail.com>
# date:     2026-10-07
# filename: proofchain/node.py
#
# peer-to-peer node: keeps a set of peers,
# gossips transactions and blocks to them and
# resolves forks by adopting the longest valid
# chain found on the network
##################################################

import logging

import httpx

from proofchain.block import Block
from proofchain.chain import Blockchain
from proofchain.transaction import Transaction
from proofchain.utils import ValidationError

log = logging.getLogger("proofchain.node")


def normalize_url(url: str) -> str:
    url = url.strip().rstrip("/")
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return url


class Node():
    def __init__(self, chain: Blockchain, miner: str = "node", self_url: str | None = None,
                 peers: list[str] | None = None, timeout: float = 5.0):
        self.chain = chain
        self.miner = miner
        self.self_url = normalize_url(self_url) if self_url else None
        self.timeout = timeout
        self.peers: set[str] = set()
        self.add_peers(peers or [])

    def add_peers(self, urls: list[str]) -> list[str]:
        added = []
        for url in urls:
            url = normalize_url(url)
            if url != self.self_url and url not in self.peers:
                self.peers.add(url)
                added.append(url)
        return added

    # ---------------------------------------------------------------- gossip

    def _post_to_peers(self, path: str, payload: dict) -> None:
        for peer in list(self.peers):
            try:
                httpx.post(f"{peer}{path}", json=payload, timeout=self.timeout)
            except httpx.HTTPError as exc:
                log.warning("could not reach peer %s: %s", peer, exc)

    def broadcast_transaction(self, tx: Transaction) -> None:
        self._post_to_peers("/transactions", tx.to_dict())

    def broadcast_block(self, block: Block) -> None:
        self._post_to_peers("/blocks", block.to_dict())

    def announce(self) -> None:
        # tells every peer about this node so they gossip back to it
        if self.self_url:
            self._post_to_peers("/peers", {"peers": [self.self_url]})

    # ------------------------------------------------------------- consensus

    def mine(self) -> Block | None:
        block = self.chain.mine_pending(self.miner)
        if block is not None:
            self.broadcast_block(block)
        return block

    def receive_block(self, data: dict) -> str:
        # returns added | known | resynced | rejected
        block = Block.from_dict(data)
        if block.index < self.chain.height and self.chain.blocks[block.index].hash == block.hash:
            return "known"
        try:
            self.chain.add_block(block)
            return "added"
        except ValidationError as exc:
            log.info("block #%s not appended directly: %s", block.index, exc)
        # a block from a longer fork: fetch full chains and pick the longest valid one
        if block.index >= self.chain.height and self.resolve_conflicts():
            return "resynced"
        return "rejected"

    def resolve_conflicts(self) -> bool:
        replaced = False
        for peer in list(self.peers):
            try:
                response = httpx.get(f"{peer}/chain", timeout=self.timeout)
                response.raise_for_status()
                blocks = [Block.from_dict(block) for block in response.json()["blocks"]]
            except (httpx.HTTPError, ValueError, KeyError, TypeError, ValidationError) as exc:
                log.warning("could not fetch chain from %s: %s", peer, exc)
                continue
            if self.chain.replace_chain(blocks):
                log.info("adopted longer chain (%d blocks) from %s", len(blocks), peer)
                replaced = True
        return replaced
