<!--
author:   mrbacco <mrbacco04@gmail.com>
date:     2026-10-07
filename: README.md
-->

# ProofChain

**Content authenticity on a blockchain.** With generated media everywhere, it is hard to prove that a photo, document or video is original and has not been changed. ProofChain lets a creator **sign the SHA3-256 hash of a file with their own key** and anchor it on a peer-to-peer blockchain. Anyone can later re-hash the file and check:

- **who** registered it (the owner's address, derived from their public key)
- **when** it was registered (the transaction timestamp and the block it is in)
- **whether it is unchanged** (any modification gives a different hash, so verification fails)

Only the hash goes on the chain. The file itself never leaves your machine.

## How it works

| Concept | Implementation |
|---|---|
| Identity | secp256k1 key pair held by the user (`wallet.pem`); address = `pc` + first 40 hex chars of SHA3-256(public key) |
| Transactions | `register` (claim a content hash) and `revoke` (the owner withdraws a proof), signed with ECDSA |
| Rules | a hash can only be held by one owner at a time; only the owner can revoke; signed transactions cannot be replayed |
| Blocks | header with prev hash, Merkle root of the transactions, difficulty, nonce; SHA3-256 proof-of-work |
| Consensus | gossip of transactions and blocks between peers; on a fork, the longest valid chain wins and transactions from abandoned blocks go back to the mempool |
| Storage | each node saves its chain as JSON (atomic writes) and fully re-validates it from genesis on startup |
| API | FastAPI REST API with CORS enabled, plus a browser UI at `/ui` |

```
proofchain/
  utils.py        canonical JSON, hashing, ValidationError
  wallet.py       key pairs, addresses, signatures
  transaction.py  register / revoke transactions
  block.py        block header, Merkle root, proof-of-work
  chain.py        ledger state, validation, consensus, persistence
  node.py         peers, gossip, conflict resolution
  api.py          REST API
  cli.py          command line (python -m proofchain ...)
  web/            browser UI served at /ui
tests/            pytest suite
legacy/           the original 2019 blockchain scripts
```

## Quick start

```bash
pip install -e ".[dev]"

# terminal 1 and 2: a two-node network
python -m proofchain node --port 5000
python -m proofchain node --port 5001 --peers http://127.0.0.1:5000

# terminal 3: create a wallet, register a file, mine, verify
python -m proofchain wallet new                 # add --password to encrypt the key
python -m proofchain register photo.jpg --title "Sunset"
python -m proofchain mine
python -m proofchain verify photo.jpg --node http://127.0.0.1:5001
python -m proofchain revoke photo.jpg
```

## Web UI

Every node serves a browser UI at **http://127.0.0.1:5000/ui/**, where you can:

- **Verify** a file by dropping it in, or by pasting a hash. The result is authentic, revoked, pending or not found.
- **Wallet:** create a key or import one, then show or back it up. To use the same identity as the CLI, run `python -m proofchain wallet export-key` and import the result in the page. `wallet import-key` does the reverse.
- **Register** a file with a title and a note, with an option to mine a block straight away.
- **My proofs:** see all your proofs and revoke them.
- **Latest blocks** and node status, with a button to mine pending transactions.

Files are hashed (SHA3-256) and transactions are signed (secp256k1) **inside the browser**, using the audited [noble](https://paulmillr.com/noble/) libraries loaded from jsdelivr. Only the hash and the signature reach the node. The key is stored in the browser's local storage, so back it up.

`verify` exits with code 1 when the file is not registered, so it can be used in scripts.

## REST API

| Method | Path | Purpose |
|---|---|---|
| GET | `/` | node info (height, tip, difficulty, peers) |
| GET | `/chain`, `/blocks/{index}` | the full chain / one block |
| GET | `/mempool` | pending transactions |
| POST | `/transactions` | submit a signed transaction |
| POST | `/mine` | mine pending transactions into a block |
| GET | `/proofs/{content_hash}` | status: `confirmed`, `revoked` or `pending` |
| GET | `/owners/{address}/proofs` | all proofs of an owner |
| POST | `/blocks` | receive a block from a peer |
| GET/POST | `/peers` | list / add peers |
| POST | `/consensus` | pull peers' chains and adopt the longest valid one |
| GET | `/validate` | re-validate the whole chain |

Interactive docs are at `http://127.0.0.1:5000/docs` while a node is running.

Signatures cover the canonical JSON of `{content_hash, metadata, public_key, timestamp, tx_type}` (sorted keys, no spaces, UTF-8, timestamps in integer milliseconds). A browser can build the same bytes, so the future web app can sign on the client side and the private key never leaves the user's device.

## Tests

```bash
python -m pytest
```

## Current limitations

- Fixed proof-of-work difficulty and no mining reward. This is fine for a consortium or demo network, but it needs difficulty adjustment and incentives before a public deployment.
- Exact-match hashing: re-encoding or resizing a file breaks the match. Perceptual hashing is a possible future extension.
- Peers are configured manually (no automatic discovery).

## License

Available under Apache 2.0 (`LICENSE-APACHE`), AGPL v3 (`LICENSE-AGPL`) or a commercial license (`COMMERCIAL-LICENSE.md`).
