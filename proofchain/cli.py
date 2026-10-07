##################################################
# author:   mrbacco <mrbacco04@gmail.com>
# date:     2026-10-07
# filename: proofchain/cli.py
#
# command line interface:
#   node      run a node (web UI at /ui)
#   wallet    create / show / export / import a key pair
#   hash      sha3-256 of a file
#   identity  publish / show the name behind an address
#   register  sign and submit a proof for a file
#   revoke    withdraw one of your proofs
#   dispute   challenge someone else's proof
#   verify    check a file against the chain
#   mine      ask a node to mine pending proofs
##################################################

import argparse
import getpass
import json
import sys
from pathlib import Path

import httpx

from proofchain.identity import WELL_KNOWN_PATH, well_known_document
from proofchain.perceptual import image_dhash
from proofchain.transaction import DISPUTE, REGISTER, REVOKE, Transaction
from proofchain.utils import ValidationError, hash_file, is_hex_digest
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


def _who(identity: dict | None, address: str) -> str:
    # "Name (verified: example.com)" or the bare address
    if not identity:
        return address
    check = identity.get("domain_check")
    if check and check["verified"]:
        badge = f"verified: {identity['domain']}"
    elif identity.get("domain"):
        badge = f"NOT verified: {check['detail'] if check else identity['domain']}"
    else:
        badge = "self-declared, no domain"
    return f"{identity['name']} ({badge}) {address}"


def _submit(args, tx: Transaction) -> None:
    _print(_request("POST", f"{args.node}/transactions", json=tx.to_dict()) | {"content_hash": tx.content_hash})


def cmd_node(args) -> None:
    import logging

    import uvicorn

    from proofchain.api import create_app
    from proofchain.chain import Blockchain
    from proofchain.identity import DomainVerifier
    from proofchain.node import Node

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
    data = args.data or f"data/node-{args.port}.json"
    self_url = args.public_url or f"http://{'127.0.0.1' if args.host in ('0.0.0.0', '::') else args.host}:{args.port}"
    node = Node(Blockchain(args.difficulty, data), miner=args.miner, self_url=self_url, peers=args.peers)
    verifier = DomainVerifier(allow_insecure=args.insecure_identity)
    if args.insecure_identity:
        print("WARNING: insecure identity mode (plain http, local hosts allowed) - for local testing only")
    if node.peers:
        node.resolve_conflicts()
        node.announce()
    print(f"ProofChain node on {self_url} | web UI {self_url}/ui/ | chain {data} | height {node.chain.height} | peers {sorted(node.peers)}")
    uvicorn.run(create_app(node, verifier), host=args.host, port=args.port, log_level="warning")


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


def cmd_wallet_export(args) -> None:
    wallet = _load_wallet(args)
    print("private key (anyone holding it can sign as you, paste it only into your own browser):")
    print(wallet.private_key_hex)


def cmd_wallet_import(args) -> None:
    try:
        wallet = Wallet.from_private_key_hex(args.private_key or getpass.getpass("private key (hex): "))
    except ValueError as exc:
        sys.exit(f"error: {exc}")
    password = getpass.getpass("new wallet password: ") if args.password else None
    try:
        wallet.save(args.wallet, password)
    except FileExistsError as exc:
        sys.exit(f"error: {exc}")
    print(f"wallet saved to {args.wallet}")
    _print({"address": wallet.address, "public_key": wallet.public_key_hex})


def cmd_hash(args) -> None:
    print(hash_file(args.file))


def cmd_identity_set(args) -> None:
    wallet = _load_wallet(args)
    try:
        tx = Transaction.identity(wallet, args.name, args.domain)
        tx.validate()
    except ValidationError as exc:
        sys.exit(f"error: {exc}")
    _print(_request("POST", f"{args.node}/transactions", json=tx.to_dict()))
    if args.domain:
        print(f"\nto get verified, publish this file at https://{tx.metadata['domain']}{WELL_KNOWN_PATH}")
        print("(it may list several addresses, e.g. one per team member):\n")
        print(well_known_document([wallet.address]))


def cmd_identity_show(args) -> None:
    address = args.address or _load_wallet(args).address
    try:
        response = httpx.get(f"{args.node}/identities/{address}", timeout=30)
    except httpx.HTTPError as exc:
        sys.exit(f"error: cannot reach node: {exc}")
    if response.status_code == 404:
        sys.exit(f"{address} has not published an identity")
    identity = response.json()
    print(_who(identity, address))
    _print(identity)


def cmd_register(args) -> None:
    wallet = _load_wallet(args)
    metadata = {key: value for key, value in (("title", args.title), ("note", args.note)) if value}
    perceptual_hash = None
    if Path(args.target).is_file():
        metadata.setdefault("filename", Path(args.target).name)
        if not args.no_perceptual:
            perceptual_hash = image_dhash(args.target)
    derived_from = _content_hash(args.derived_from) if args.derived_from else None
    tx = Transaction.create(wallet, REGISTER, _content_hash(args.target), metadata,
                            perceptual_hash=perceptual_hash, derived_from=derived_from)
    _submit(args, tx)


def cmd_revoke(args) -> None:
    wallet = _load_wallet(args)
    _submit(args, Transaction.create(wallet, REVOKE, _content_hash(args.target)))


def cmd_dispute(args) -> None:
    wallet = _load_wallet(args)
    evidence = _content_hash(args.evidence) if args.evidence else None
    tx = Transaction.create(wallet, DISPUTE, _content_hash(args.target), {"reason": args.reason}, evidence=evidence)
    _submit(args, tx)


def _print_similar(args) -> None:
    perceptual_hash = image_dhash(args.target) if Path(args.target).is_file() else None
    if not perceptual_hash:
        return
    matches = _request("GET", f"{args.node}/similar/{perceptual_hash}")["matches"]
    if not matches:
        print("no similar registered images either")
        return
    print(f"\nbut {len(matches)} registered image(s) look similar (possibly an edited or re-encoded copy):")
    for match in matches:
        print(f"  {match['distance']:>2}/64 bits differ  {match['status']:<9} "
              f"{match['metadata'].get('title') or match['metadata'].get('filename', '')}  "
              f"by {_who(match['owner_identity'], match['owner'])}")


def cmd_verify(args) -> None:
    content_hash = _content_hash(args.target)
    try:
        response = httpx.get(f"{args.node}/proofs/{content_hash}", timeout=30)
    except httpx.HTTPError as exc:
        sys.exit(f"error: cannot reach node: {exc}")
    if response.status_code == 404:
        print(f"NOT FOUND: no proof for {content_hash} (unregistered, or the file was modified)")
        _print_similar(args)
        sys.exit(1)
    record = response.json()
    print(f"{record['status'].upper()}: registered by {_who(record['owner_identity'], record['owner'])}")
    if record.get("derived_from"):
        original = record.get("derived_from_record")
        print(f"derived from original {record['derived_from'][:16]}... "
              + (f"registered {original['timestamp']} ({original['status']})" if original else "(not found)"))
    for dispute in record["disputes"]:
        evidence = f", evidence registered at {dispute['evidence_timestamp']}" if dispute["evidence"] else ""
        print(f"DISPUTED by {_who(dispute['disputer_identity'], dispute['disputer'])}: {dispute['reason']}{evidence}")
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
    p.add_argument("--insecure-identity", action="store_true",
                   help="verify identity domains over plain http, including local hosts (testing only)")
    p.set_defaults(func=cmd_node)

    wallet = sub.add_parser("wallet", help="manage your key pair").add_subparsers(dest="wallet_command", required=True)
    p = wallet.add_parser("new", help="create a new wallet")
    with_wallet(p)
    p.set_defaults(func=cmd_wallet_new)
    p = wallet.add_parser("show", help="show address and public key")
    with_wallet(p)
    p.set_defaults(func=cmd_wallet_show)
    p = wallet.add_parser("export-key", help="print the raw private key (for the web UI)")
    with_wallet(p)
    p.set_defaults(func=cmd_wallet_export)
    p = wallet.add_parser("import-key", help="save a raw private key (e.g. from the web UI) as a wallet")
    p.add_argument("private_key", nargs="?", help="64 hex chars (prompted if omitted)")
    with_wallet(p)
    p.set_defaults(func=cmd_wallet_import)

    identity = sub.add_parser("identity", help="publish / show the name behind an address").add_subparsers(
        dest="identity_command", required=True)
    p = identity.add_parser("set", help="publish your name, optionally with a domain that vouches for it")
    p.add_argument("--name", required=True)
    p.add_argument("--domain", help="e.g. example.com (verified via /.well-known/proofchain.json)")
    with_wallet(p)
    with_node(p)
    p.set_defaults(func=cmd_identity_set)
    p = identity.add_parser("show", help="show the identity of an address (default: your wallet)")
    p.add_argument("address", nargs="?")
    with_wallet(p)
    with_node(p)
    p.set_defaults(func=cmd_identity_show)

    p = sub.add_parser("hash", help="print the sha3-256 of a file")
    p.add_argument("file")
    p.set_defaults(func=cmd_hash)

    p = sub.add_parser("register", help="sign and submit a proof for a file or hash")
    p.add_argument("target", help="file path or sha3-256 hex digest")
    p.add_argument("--title")
    p.add_argument("--note")
    p.add_argument("--derived-from", metavar="ORIGINAL",
                   help="file or hash of your earlier registered original (e.g. the unpublished RAW)")
    p.add_argument("--no-perceptual", action="store_true", help="do not attach a perceptual hash for images")
    with_wallet(p)
    with_node(p)
    p.set_defaults(func=cmd_register)

    p = sub.add_parser("revoke", help="revoke one of your proofs")
    p.add_argument("target", help="file path or sha3-256 hex digest")
    with_wallet(p)
    with_node(p)
    p.set_defaults(func=cmd_revoke)

    p = sub.add_parser("dispute", help="challenge someone else's proof")
    p.add_argument("target", help="file path or sha3-256 hex digest of the disputed proof")
    p.add_argument("--reason", required=True)
    p.add_argument("--evidence", help="file or hash of your own earlier registration backing the claim")
    with_wallet(p)
    with_node(p)
    p.set_defaults(func=cmd_dispute)

    p = sub.add_parser("verify", help="check a file or hash against the chain")
    p.add_argument("target", help="file path or sha3-256 hex digest")
    with_node(p)
    p.set_defaults(func=cmd_verify)

    p = sub.add_parser("mine", help="ask a node to mine pending proofs")
    with_node(p)
    p.set_defaults(func=cmd_mine)

    return parser


def main(argv: list[str] | None = None) -> None:
    # names and titles may contain any character; never crash on a legacy console encoding
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="replace")
    args = build_parser().parse_args(argv)
    if hasattr(args, "node") and isinstance(args.node, str):
        args.node = args.node.rstrip("/")
    args.func(args)


if __name__ == "__main__":
    main()
