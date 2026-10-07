<!--
author:   mrbacco <mrbacco04@gmail.com>
date:     2026-10-07
filename: README.md
-->

# ProofChain

**Content authenticity on a blockchain.** With generated media everywhere, it is hard to prove that a photo, document or video is original and has not been changed. ProofChain lets a creator **sign the SHA3-256 hash of a file with their own key** and anchor it on a peer-to-peer blockchain. Anyone can later re-hash the file and check:

- **who** registered it (the owner's address, and the name behind it when a domain vouches for it)
- **when** it was registered (the transaction timestamp and the block it is in)
- **whether it is unchanged** (any modification gives a different hash, so verification fails)

Only the hash goes on the chain. The file itself never leaves your machine.

## How it works

| Concept | Implementation |
|---|---|
| Identity | secp256k1 key pair held by the user (`wallet.pem`); address = `pc` + first 40 hex chars of SHA3-256(public key) |
| Transactions | `register` (claim a content hash), `revoke` (the owner withdraws a proof), `dispute` (challenge someone else's proof) and `identity` (name + domain for an address), all signed with ECDSA |
| Rules | a hash can only be held by one owner at a time; only the owner can revoke; `derived_from` and dispute evidence must point to the signer's own registrations; signed transactions cannot be replayed |
| Blocks | header with prev hash, Merkle root of the transactions, difficulty, nonce; SHA3-256 proof-of-work |
| Consensus | gossip of transactions and blocks between peers; on a fork, the longest valid chain wins and transactions from abandoned blocks go back to the mempool |
| Storage | each node saves its chain as JSON (atomic writes) and fully re-validates it from genesis on startup |
| API | FastAPI REST API with CORS enabled, plus a browser UI at `/ui` |

```
proofchain/
  utils.py        canonical JSON, hashing, ValidationError
  wallet.py       key pairs, addresses, signatures
  transaction.py  register / revoke / dispute / identity transactions
  block.py        block header, Merkle root, proof-of-work
  chain.py        ledger state, validation, consensus, persistence
  identity.py     domain verification of identities (/.well-known/proofchain.json)
  perceptual.py   perceptual image hash (dHash) for finding edited copies
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

## Trust features

Hashes and signatures alone prove that *a key* had *a file* at *a time*. Three features close the gap to "this person made this":

### 1. Verified identities: who is behind an address?

```bash
python -m proofchain identity set --name "Mario Rossi" --domain mariorossi.com
```

This publishes the name on the chain and prints a small file to put at `https://mariorossi.com/.well-known/proofchain.json`:

```json
{ "addresses": ["pc78bd5f0839c94b43a24498ccc3a69976d2573a6c"] }
```

Anyone can *claim* any name, but only the real owner of the domain can publish that file. Verifiers see **Mario Rossi ✓ mariorossi.com** for the real owner and **Mario Rossi UNVERIFIED** for an impersonator. One domain may list several addresses (e.g. a newsroom's photographers). The check runs when data is read, never during consensus, and results are cached. The node only fetches public https hosts (no private IPs, custom ports or redirects). Use `node --insecure-identity` to test against a local web server.

### 2. Provenance: being first is not the same as being the author

Whoever registers a hash first owns that hash, so a thief who copies your published photo could register it before you. Two defences:

- **Register the unpublished original first**, then register what you publish as **derived from** it:
  ```bash
  python -m proofchain register sunset-RAW.dng --title "Sunset RAW"
  python -m proofchain register sunset.jpg --derived-from sunset-RAW.dng
  ```
  A thief can grab the public JPEG, but never the RAW that only you hold. `derived_from` must point to one of your own registrations.
- **Dispute** a claim. The dispute is recorded on the chain next to the proof, optionally citing your own earlier registration as evidence:
  ```bash
  python -m proofchain dispute stolen.jpg --reason "my photo, RAW registered earlier" --evidence sunset-RAW.dng
  ```
  Verifiers see the dispute, who filed it (with their verified identity) and whether the evidence predates the claim.

### 3. Similar images: finding edited copies

SHA3 changes completely when a single byte changes, so a resized or re-compressed copy no longer matches. For images, registrations also carry a 64-bit **perceptual hash** (dHash), which stays almost the same when an image is resized, re-encoded or lightly edited. When an exact match fails, `verify` and the web UI list registered images that look the same:

```
NOT FOUND: no proof for 07447b20... (unregistered, or the file was modified)
but 1 registered image(s) look similar (possibly an edited or re-encoded copy):
   0/64 bits differ  confirmed Sunset  by Mario Rossi (verified: mariorossi.com) pc78bd...
```

The CLI computes it with Pillow (`pip install -e ".[images]"`); the browser runs the identical algorithm (`dhash-v1`, documented in `perceptual.py`), and both give exactly the same hash. A perceptual hash is a search aid supplied by the registrant: authenticity is still decided by the exact SHA3 match.

## Web UI

Every node serves a browser UI at **http://127.0.0.1:5000/ui/**, where you can:

- **Verify** a file by dropping it in, or by pasting a hash. The result is authentic, disputed, revoked, pending or not found, and shows the owner's verified identity, the derived-from link, any disputes and, when there's no exact match, similar registered images.
- **Wallet:** create a key or import one, then show or back it up. To use the same identity as the CLI, run `python -m proofchain wallet export-key` and import the result in the page. `wallet import-key` does the reverse.
- **Public identity:** publish your name and domain. The page shows the file to put on your website.
- **Register** a file with a title, a note and an optional "derived from" original, with an option to mine a block straight away.
- **Dispute** someone else's proof straight from the verify result.
- **My proofs:** see all your proofs, with any disputes, and revoke them.
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
| GET | `/proofs/{content_hash}` | status (`confirmed`, `revoked`, `pending`), owner identity, derived-from link, disputes |
| GET | `/similar/{perceptual_hash}` | registered images within `max_distance` bits (default 10 of 64) |
| GET | `/owners/{address}/proofs` | an owner's identity and all their proofs |
| GET | `/identities/{address}` | on-chain identity plus the live domain check |
| POST | `/blocks` | receive a block from a peer |
| GET/POST | `/peers` | list / add peers |
| POST | `/consensus` | pull peers' chains and adopt the longest valid one |
| GET | `/validate` | re-validate the whole chain |

Interactive docs are at `http://127.0.0.1:5000/docs` while a node is running.

Signatures cover the canonical JSON of `{content_hash, metadata, public_key, timestamp, tx_type}`, plus `perceptual_hash`, `derived_from` or `evidence` only when they are set (sorted keys, no spaces, UTF-8, timestamps in integer milliseconds). A browser builds the same bytes, so signing happens on the client side and the private key never leaves the user's device. Because unset fields are left out, transactions created before these fields existed keep the same bytes and stay valid.

## Tests

```bash
python -m pytest
```

## Current limitations

- Fixed proof-of-work difficulty and no mining reward. This is fine for a consortium or demo network, but it needs difficulty adjustment and incentives before a public deployment.
- Perceptual matching covers images only (not video, audio or documents), and dHash can be fooled by heavy edits such as large crops, mirroring or rotation.
- Disputes are recorded, not judged: the chain shows the evidence, and people decide whom to believe.
- Domain verification proves control of a website, not a legal identity, and an identity is only as trustworthy as the domain behind it.
- Peers are configured manually (no automatic discovery).

## License

Available under Apache 2.0 (`LICENSE-APACHE`), AGPL v3 (`LICENSE-AGPL`) or a commercial license (`COMMERCIAL-LICENSE.md`).
