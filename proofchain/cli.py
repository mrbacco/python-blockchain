##################################################
# author:   mrbacco <mrbacco04@gmail.com>
# date:     2026-10-07
# filename: proofchain/cli.py
#
# command line interface:
#   node      run a node
#   wallet    create / show a key pair
#   hash      sha3-256 of a file
#   register  sign and submit a proof for a file
#   revoke    withdraw one of your proofs
#   verify    check a file against the chain
#   mine      ask a node to mine pending proofs
##################################################

import argparse
import getpass
import json
import sys
from pathlib import Path

import httpx

from proofchain.transaction import REGISTER, REVOKE, Transaction
from proofchain.utils import hash_file, is_hex_digest
from proofchain.wallet import Wallet

DEFAULT_WALLET = Path.home() / ".proofchain" / "wallet.pem"
DEFAULT_NODE = "http://127.0.0.1:5000"


def _content_hash(target: str) -> str:
    # accepts a file path or an already computed hash
    if Path(target).is_file():
        return hash_file(target)
    if is_hex_digest(target.lower()):
        return target.lower()
    sys.exit(f"error: {target!r} is neither a file nor a sha3-256 hex digest")


def _load_wallet(args) -> Wallet:
    password = getpass.getpass("wallet password: ") if args.password else None
    try:
        return Wallet.load(args.wallet, password)
    except FileNotFoundError:
        sys.exit(f"error: no wallet at {args.wallet} (create one with: python -m proofchain wallet new)")


def _request(method: str, url: str, **kwargs) -> dict:
    try:
        response = httpx.request(method, url, timeout=60, **kwargs)
    except httpx.HTTPError as exc:
        sys.exit(f"error: cannot reach node: {exc}")
    if response.status_code >= 400:
        try:
            detail = response.json().get("detail", response.text)
        except ValueError:
            detail = response.text
        sys.exit(f"error ({response.status_code}): {detail}")
    return response.json()


def _print(data) -> None:
    print(json.dumps(data, indent=2))


def cmd_node(args) -> None:
    import logging

    import uvicorn

    from proofchain.api import create_app
    from proofchain.chain import Blockchain
    from proofchain.node import Node

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
    data = args.data or f"data/node-{args.port}.json"
    self_url = args.public_url or f"http://{'127.0.0.1' if args.host in ('0.0.0.0', '::') else args.host}:{args.port}"
    node = Node(Blockchain(args.difficulty, data), miner=args.miner, self_url=self_url, peers=args.peers)
    if node.peers:
        node.resolve_conflicts()
        node.announce()
    print(f"ProofChain node on {self_url} | chain {data} | height {node.chain.height} | peers {sorted(node.peers)}")
    uvicorn.run(create_app(node), host=args.host, port=args.port, log_level="warning")


def cmd_wallet_new(args) -> None:
    password = None
    if args.password:
        password = getpass.getpass("new wallet password: ")
        if password != getpass.getpass("repeat password: "):
            sys.exit("error: passwords do not match")
    wallet = Wallet()
    try:
        wallet.save(args.wallet, password)
    except FileExistsError as exc:
        sys.exit(f"error: {exc}")
    print(f"wallet saved to {args.wallet} (keep it private, it cannot be recovered)")
    _print({"address": wallet.address, "public_key": wallet.public_key_hex})


def cmd_wallet_show(args) -> None:
    wallet = _load_wallet(args)
    _print({"address": wallet.address, "public_key": wallet.public_key_hex})


def cmd_hash(args) -> None:
    print(hash_file(args.file))


def cmd_register(args) -> None:
    wallet = _load_wallet(args)
    metadata = {key: value for key, value in (("title", args.title), ("note", args.note)) if value}
    if Path(args.target).is_file():
        metadata.setdefault("filename", Path(args.target).name)
    tx = Transaction.create(wallet, REGISTER, _content_hash(args.target), metadata)
    _print(_request("POST", f"{args.node}/transactions", json=tx.to_dict()) | {"content_hash": tx.content_hash})


def cmd_revoke(args) -> None:
    wallet = _load_wallet(args)
    tx = Transaction.create(wallet, REVOKE, _content_hash(args.target))
    _print(_request("POST", f"{args.node}/transactions", json=tx.to_dict()) | {"content_hash": tx.content_hash})


def cmd_verify(args) -> None:
    content_hash = _content_hash(args.target)
    try:
        response = httpx.get(f"{args.node}/proofs/{content_hash}", timeout=30)
    except httpx.HTTPError as exc:
        sys.exit(f"error: cannot reach node: {exc}")
    if response.status_code == 404:
        print(f"NOT FOUND: no proof for {content_hash} (unregistered, or the file was modified)")
        sys.exit(1)
    record = response.json()
    print(f"{record['status'].upper()}: registered by {record['owner']}")
    _print(record)


def cmd_mine(args) -> None:
    _print(_request("POST", f"{args.node}/mine"))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="proofchain", description="ProofChain: content authenticity on a blockchain")
    sub = parser.add_subparsers(dest="command", required=True)

    def with_wallet(p):
        p.add_argument("--wallet", type=Path, default=DEFAULT_WALLET, help=f"key file (default {DEFAULT_WALLET})")
        p.add_argument("--password", action="store_true", help="the wallet is password protected")

    def with_node(p):
        p.add_argument("--node", default=DEFAULT_NODE, help=f"node url (default {DEFAULT_NODE})")

    p = sub.add_parser("node", help="run a node")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=5000)
    p.add_argument("--data", help="chain file (default data/node-<port>.json)")
    p.add_argument("--difficulty", type=int, default=4, help="leading zero hex digits required by proof-of-work")
    p.add_argument("--miner", default="node", help="label/address recorded in mined blocks")
    p.add_argument("--peers", nargs="*", default=[], help="peer node urls")
    p.add_argument("--public-url", help="url peers use to reach this node")
    p.set_defaults(func=cmd_node)

    wallet = sub.add_parser("wallet", help="manage your key pair").add_subparsers(dest="wallet_command", required=True)
    p = wallet.add_parser("new", help="create a new wallet")
    with_wallet(p)
    p.set_defaults(func=cmd_wallet_new)
    p = wallet.add_parser("show", help="show address and public key")
    with_wallet(p)
    p.set_defaults(func=cmd_wallet_show)

    p = sub.add_parser("hash", help="print the sha3-256 of a file")
    p.add_argument("file")
    p.set_defaults(func=cmd_hash)

    p = sub.add_parser("register", help="sign and submit a proof for a file or hash")
    p.add_argument("target", help="file path or sha3-256 hex digest")
    p.add_argument("--title")
    p.add_argument("--note")
    with_wallet(p)
    with_node(p)
    p.set_defaults(func=cmd_register)

    p = sub.add_parser("revoke", help="revoke one of your proofs")
    p.add_argument("target", help="file path or sha3-256 hex digest")
    with_wallet(p)
    with_node(p)
    p.set_defaults(func=cmd_revoke)

    p = sub.add_parser("verify", help="check a file or hash against the chain")
    p.add_argument("target", help="file path or sha3-256 hex digest")
    with_node(p)
    p.set_defaults(func=cmd_verify)

    p = sub.add_parser("mine", help="ask a node to mine pending proofs")
    with_node(p)
    p.set_defaults(func=cmd_mine)

    return parser


def main(argv: list[str] | None = None) -> None:
    args = build_parser().parse_args(argv)
    if hasattr(args, "node") and isinstance(args.node, str):
        args.node = args.node.rstrip("/")
    args.func(args)


if __name__ == "__main__":
    main()
