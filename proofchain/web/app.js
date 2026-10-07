/*
author:   mrbacco <mrbacco04@gmail.com>
date:     2026-10-07
filename: proofchain/web/app.js

browser side of ProofChain: SHA3-256 file hashing,
secp256k1 key management and signing (same canonical
JSON + ECDSA/SHA-256 + DER format as the Python node),
and calls to the node REST API
*/

import * as secp from "https://cdn.jsdelivr.net/npm/@noble/secp256k1@2.1.0/+esm";
import { sha3_256 } from "https://cdn.jsdelivr.net/npm/@noble/hashes@1.4.0/sha3/+esm";

const KEY_STORAGE = "proofchain.privateKey";
const CHUNK_SIZE = 4 * 1024 * 1024;
const REFRESH_MS = 5000;

const $ = (id) => document.getElementById(id);

// ------------------------------------------------------------------ helpers

const toHex = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");

function fromHex(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}

const isHash = (value) => /^[0-9a-f]{64}$/.test(value);
const short = (hex, n = 10) => (hex.length > 2 * n ? `${hex.slice(0, n)}…${hex.slice(-6)}` : hex);
const formatTime = (ms) => new Date(ms).toLocaleString();

// small DOM builder: text is always set via textContent (no HTML injection)
function el(tag, props = {}, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(props)) {
    if (key === "class") node.className = value;
    else if (key === "text") node.textContent = value;
    else if (key.startsWith("on")) node.addEventListener(key.slice(2), value);
    else node.setAttribute(key, value);
  }
  for (const child of children) if (child != null) node.append(child);
  return node;
}

let toastTimer;
function toast(message, isError = false) {
  const box = $("toast");
  box.textContent = message;
  box.className = isError ? "toast error" : "toast";
  box.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => (box.hidden = true), isError ? 6000 : 3000);
}

// --------------------------------------------------------------------- api

async function api(path, options = {}) {
  const response = await fetch(path, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) {
    const detail = typeof body.detail === "string" ? body.detail : JSON.stringify(body.detail ?? response.statusText);
    const error = new Error(detail);
    error.status = response.status;
    throw error;
  }
  return body;
}

// ------------------------------------------------------------------ crypto

// must produce exactly the bytes of Python's
// json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value !== null && typeof value === "object") {
    return `{${Object.keys(value).sort().map((k) => `${JSON.stringify(k)}:${canonicalJson(value[k])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

async function hashFile(file, onProgress) {
  const hasher = sha3_256.create();
  for (let offset = 0; offset < file.size; offset += CHUNK_SIZE) {
    const chunk = await file.slice(offset, offset + CHUNK_SIZE).arrayBuffer();
    hasher.update(new Uint8Array(chunk));
    onProgress?.(Math.min(1, (offset + CHUNK_SIZE) / file.size));
  }
  return toHex(hasher.digest());
}

// DER encoding of an ECDSA (r, s) pair, the format Python's cryptography verifies
function derInteger(value) {
  let hex = value.toString(16);
  if (hex.length % 2) hex = "0" + hex;
  let bytes = Array.from(fromHex(hex));
  if (bytes[0] & 0x80) bytes = [0, ...bytes];
  return [0x02, bytes.length, ...bytes];
}

function derSignature(r, s) {
  const body = [...derInteger(r), ...derInteger(s)];
  return toHex(new Uint8Array([0x30, body.length, ...body]));
}

const wallet = {
  privateKey: null,

  load() {
    try { this.privateKey = localStorage.getItem(KEY_STORAGE); } catch { this.privateKey = null; }
    if (this.privateKey && !secp.utils.isValidPrivateKey(this.privateKey)) this.privateKey = null;
  },

  set(privateKeyHex) {
    if (!secp.utils.isValidPrivateKey(privateKeyHex)) throw new Error("invalid private key: expected 64 hex characters");
    this.privateKey = privateKeyHex;
    try { localStorage.setItem(KEY_STORAGE, privateKeyHex); } catch { toast("could not persist the key in this browser", true); }
  },

  forget() {
    this.privateKey = null;
    try { localStorage.removeItem(KEY_STORAGE); } catch { /* nothing stored */ }
  },

  get publicKey() {
    return toHex(secp.getPublicKey(this.privateKey, true));
  },

  get address() {
    return "pc" + toHex(sha3_256(fromHex(this.publicKey))).slice(0, 40);
  },

  async sign(bytes) {
    // ECDSA over SHA-256(data), same as ec.ECDSA(hashes.SHA256()) in Python
    const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
    const signature = await secp.signAsync(digest, this.privateKey);
    return derSignature(signature.r, signature.s);
  },
};

async function buildTransaction(txType, contentHash, metadata = {}) {
  const payload = {
    tx_type: txType,
    content_hash: contentHash,
    public_key: wallet.publicKey,
    timestamp: Date.now(),
    metadata,
  };
  const signature = await wallet.sign(new TextEncoder().encode(canonicalJson(payload)));
  return { ...payload, signature };
}

// ------------------------------------------------------------------ status

async function refreshStatus() {
  try {
    const info = await api("/");
    $("node-dot").className = "dot ok";
    $("node-label").textContent = location.host;
    $("stat-height").textContent = info.height;
    $("stat-pending").textContent = info.pending;
    $("stat-peers").textContent = info.peers.length;
  } catch {
    $("node-dot").className = "dot bad";
    $("node-label").textContent = "node offline";
  }
}

async function refreshBlocks() {
  const list = $("blocks");
  try {
    const { blocks } = await api("/chain");
    list.replaceChildren(
      ...blocks.slice(-10).reverse().map((block) =>
        el("li", {},
          el("div", { class: "item-main" },
            el("div", { class: "item-title", text: `#${block.index}  ${block.index === 0 ? "genesis" : `${block.transactions.length} tx`}` }),
            el("div", { class: "item-sub mono", text: short(block.hash, 16) }),
            el("div", { class: "item-sub", text: `${formatTime(block.timestamp)} · nonce ${block.nonce} · ${block.miner}` }),
          ),
        ),
      ),
    );
  } catch {
    list.replaceChildren(el("li", { class: "empty", text: "Could not load blocks." }));
  }
}

async function refreshMyProofs() {
  const list = $("my-proofs");
  if (!wallet.privateKey) {
    list.replaceChildren(el("li", { class: "empty", text: "Create or import a wallet to see your proofs." }));
    return;
  }
  try {
    const [{ proofs }, { transactions }] = await Promise.all([
      api(`/owners/${wallet.address}/proofs`),
      api("/mempool"),
    ]);
    const mine = transactions.filter((tx) => tx.public_key === wallet.publicKey);
    const pendingRevokes = new Set(mine.filter((tx) => tx.tx_type === "revoke").map((tx) => tx.content_hash));
    const pendingRegisters = mine
      .filter((tx) => tx.tx_type === "register")
      .map((tx) => ({ ...tx, status: "pending" }));
    const confirmed = proofs
      .filter((proof) => !pendingRegisters.some((tx) => tx.content_hash === proof.content_hash))
      .map((proof) => ({
        ...proof,
        status: pendingRevokes.has(proof.content_hash) ? "pending" : proof.revoked ? "revoked" : "confirmed",
      }));
    const items = [...pendingRegisters, ...confirmed].sort((a, b) => b.timestamp - a.timestamp);

    if (!items.length) {
      list.replaceChildren(el("li", { class: "empty", text: "No proofs yet. Register a file to create one." }));
      return;
    }
    list.replaceChildren(
      ...items.map((item) => {
        const name = item.metadata.title || item.metadata.filename || "untitled";
        const revoke = item.status === "confirmed"
          ? el("button", { class: "danger", text: "Revoke", onclick: () => revokeProof(item.content_hash, name) })
          : null;
        return el("li", {},
          el("div", { class: "item-main" },
            el("div", { class: "item-title" }, `${name} `, el("span", { class: `badge ${item.status}`, text: item.status })),
            el("div", { class: "item-sub mono", text: short(item.content_hash, 16) }),
            el("div", { class: "item-sub", text: formatTime(item.timestamp) }),
          ),
          revoke,
        );
      }),
    );
  } catch (error) {
    list.replaceChildren(el("li", { class: "empty", text: `Could not load proofs: ${error.message}` }));
  }
}

function refreshAll() {
  return Promise.all([refreshStatus(), refreshBlocks(), refreshMyProofs()]);
}

// ------------------------------------------------------------------ wallet

function renderWallet() {
  const ready = Boolean(wallet.privateKey);
  $("wallet-empty").hidden = ready;
  $("wallet-ready").hidden = !ready;
  $("wallet-secret").hidden = true;
  $("wallet-export").textContent = "Show private key";
  if (ready) $("wallet-address").textContent = wallet.address;
  updateRegisterButton();
}

$("wallet-create").addEventListener("click", () => {
  wallet.set(toHex(secp.utils.randomPrivateKey()));
  renderWallet();
  refreshMyProofs();
  toast("Wallet created. Back up your private key.");
});

$("wallet-import-form").addEventListener("submit", (event) => {
  event.preventDefault();
  const input = $("wallet-import-key");
  try {
    wallet.set(input.value.trim().toLowerCase().replace(/^0x/, ""));
  } catch (error) {
    toast(error.message, true);
    return;
  }
  input.value = "";
  renderWallet();
  refreshMyProofs();
  toast("Wallet imported.");
});

$("wallet-copy").addEventListener("click", async () => {
  try {
    await navigator.clipboard.writeText(wallet.address);
    toast("Address copied.");
  } catch {
    toast("Could not access the clipboard.", true);
  }
});

$("wallet-export").addEventListener("click", () => {
  const secret = $("wallet-secret");
  secret.hidden = !secret.hidden;
  secret.textContent = secret.hidden ? "" : wallet.privateKey;
  $("wallet-export").textContent = secret.hidden ? "Show private key" : "Hide private key";
});

$("wallet-forget").addEventListener("click", () => {
  if (!confirm("Remove the key from this browser? Without a backup you can no longer revoke your proofs.")) return;
  wallet.forget();
  renderWallet();
  refreshMyProofs();
});

// ------------------------------------------------------------------ verify

function showVerifyResult(contentHash, proof) {
  const box = $("verify-result");
  box.hidden = false;
  if (!proof) {
    box.className = "result";
    box.replaceChildren(
      el("h3", { text: "Not found" }),
      el("p", { class: "hint", text: "No proof exists for this content. Either it was never registered, or the file has been modified." }),
      el("dl", {}, el("dt", { text: "SHA3-256" }), el("dd", { class: "mono", text: contentHash })),
    );
    return;
  }
  const titles = { confirmed: "Authentic: registered and unchanged", revoked: "Revoked by its owner", pending: "Pending: waiting to be mined" };
  const classes = { confirmed: "ok", revoked: "bad", pending: "warn" };
  const isMine = wallet.privateKey && proof.owner === wallet.address;
  const rows = [
    ["Owner", el("span", { class: "mono" }, proof.owner, isMine ? " " : null, isMine ? el("span", { class: "badge you", text: "you" }) : null)],
    ["Registered", formatTime(proof.timestamp)],
    ["Block", proof.block_index >= 0 ? `#${proof.block_index}` : "not yet mined"],
    ...Object.entries(proof.metadata).map(([key, value]) => [key[0].toUpperCase() + key.slice(1), value]),
    ["SHA3-256", el("span", { class: "mono", text: proof.content_hash })],
    ["Transaction", el("span", { class: "mono", text: proof.tx_id })],
  ];
  if (proof.revoked) rows.splice(3, 0, ["Revoked", formatTime(proof.revoked_at)]);
  box.className = `result ${classes[proof.status]}`;
  box.replaceChildren(
    el("h3", { text: titles[proof.status] }),
    el("dl", {}, ...rows.flatMap(([label, value]) => [el("dt", { text: label }), el("dd", {}, value)])),
  );
}

async function verifyHash(contentHash) {
  try {
    showVerifyResult(contentHash, await api(`/proofs/${contentHash}`));
  } catch (error) {
    if (error.status === 404) showVerifyResult(contentHash, null);
    else toast(`Verification failed: ${error.message}`, true);
  }
}

async function verifyFile(file) {
  const label = $("verify-drop-text");
  label.textContent = `Hashing ${file.name}…`;
  try {
    const contentHash = await hashFile(file, (p) => (label.textContent = `Hashing ${file.name}… ${Math.round(p * 100)}%`));
    label.textContent = `${file.name} — drop another file to check it`;
    await verifyHash(contentHash);
  } catch (error) {
    label.textContent = "Drop a file here or click to choose";
    toast(`Could not read the file: ${error.message}`, true);
  }
}

$("verify-file").addEventListener("change", (event) => {
  const [file] = event.target.files;
  if (file) verifyFile(file);
  event.target.value = "";
});

$("verify-hash-form").addEventListener("submit", (event) => {
  event.preventDefault();
  const value = $("verify-hash").value.trim().toLowerCase();
  if (!isHash(value)) {
    toast("A SHA3-256 hash is 64 hexadecimal characters.", true);
    return;
  }
  verifyHash(value);
});

// ---------------------------------------------------------------- register

let registerFile = null;
let registerHash = null;

function updateRegisterButton() {
  const button = $("register-btn");
  button.disabled = !(wallet.privateKey && registerHash);
  button.title = !wallet.privateKey ? "Create or import a wallet first" : !registerHash ? "Choose a file first" : "";
}

async function selectRegisterFile(file) {
  registerFile = file;
  registerHash = null;
  updateRegisterButton();
  $("register-drop-text").textContent = file.name;
  $("register-hash").textContent = "hashing…";
  try {
    registerHash = await hashFile(file, (p) => ($("register-hash").textContent = `hashing… ${Math.round(p * 100)}%`));
    $("register-hash").textContent = `SHA3-256 ${registerHash}`;
  } catch (error) {
    $("register-hash").textContent = "";
    toast(`Could not read the file: ${error.message}`, true);
  }
  updateRegisterButton();
}

$("register-file").addEventListener("change", (event) => {
  const [file] = event.target.files;
  if (file) selectRegisterFile(file);
  event.target.value = "";
});

$("register-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!wallet.privateKey || !registerHash) return;
  const metadata = { filename: registerFile.name };
  const title = $("register-title").value.trim();
  const note = $("register-note").value.trim();
  if (title) metadata.title = title;
  if (note) metadata.note = note;

  const button = $("register-btn");
  const result = $("register-result");
  button.disabled = true;
  button.textContent = "Signing…";
  try {
    const tx = await buildTransaction("register", registerHash, metadata);
    await api("/transactions", { method: "POST", body: JSON.stringify(tx) });
    let message = "Proof submitted. It is pending until a block is mined.";
    if ($("register-mine").checked) {
      button.textContent = "Mining…";
      const mined = await api("/mine", { method: "POST" });
      if (mined.mined) message = `Proof confirmed in block #${mined.block.index}.`;
    }
    result.className = "result ok";
    result.replaceChildren(el("h3", { text: "Registered" }), el("p", { text: message }));
    result.hidden = false;
    $("register-title").value = "";
    $("register-note").value = "";
    $("register-drop-text").textContent = "Choose the original file";
    $("register-hash").textContent = "";
    registerFile = registerHash = null;
  } catch (error) {
    result.className = "result bad";
    result.replaceChildren(el("h3", { text: "Not registered" }), el("p", { text: error.message }));
    result.hidden = false;
  } finally {
    button.textContent = "Sign & register";
    updateRegisterButton();
    refreshAll();
  }
});

// ------------------------------------------------------------------ revoke

async function revokeProof(contentHash, name) {
  if (!confirm(`Revoke the proof for "${name}"? Anyone verifying this file will see it as revoked.`)) return;
  try {
    const tx = await buildTransaction("revoke", contentHash);
    await api("/transactions", { method: "POST", body: JSON.stringify(tx) });
    const mined = await api("/mine", { method: "POST" });
    toast(mined.mined ? `Revoked in block #${mined.block.index}.` : "Revocation submitted.");
  } catch (error) {
    toast(`Revoke failed: ${error.message}`, true);
  }
  refreshAll();
}

// -------------------------------------------------------------------- mine

$("mine-btn").addEventListener("click", async () => {
  const button = $("mine-btn");
  button.disabled = true;
  button.textContent = "Mining…";
  try {
    const result = await api("/mine", { method: "POST" });
    toast(result.mined ? `Mined block #${result.block.index}.` : "Nothing to mine.");
  } catch (error) {
    toast(`Mining failed: ${error.message}`, true);
  } finally {
    button.disabled = false;
    button.textContent = "Mine pending";
    refreshAll();
  }
});

// ------------------------------------------------------------- drag & drop

for (const [zoneId, handler] of [["verify-drop", verifyFile], ["register-drop", selectRegisterFile]]) {
  const zone = $(zoneId);
  zone.addEventListener("dragover", (event) => { event.preventDefault(); zone.classList.add("over"); });
  zone.addEventListener("dragleave", () => zone.classList.remove("over"));
  zone.addEventListener("drop", (event) => {
    event.preventDefault();
    zone.classList.remove("over");
    const [file] = event.dataTransfer.files;
    if (file) handler(file);
  });
}

// -------------------------------------------------------------------- init

wallet.load();
renderWallet();
refreshAll();
setInterval(refreshAll, REFRESH_MS);
