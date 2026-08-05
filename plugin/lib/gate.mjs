/**
 * Billing gate — the CLI counterpart of the extension's gate in extension/content.js.
 *
 * Same contract, deliberately:
 *   • It only redacts when a VALID, IN-QUOTA workspace key is present.
 *   • It fails CLOSED. Until the server confirms a good key, PII-carrying content is
 *     WITHHELD, never passed through. "Stop redacting" must never mean "start leaking".
 *   • A previously-validated key stays open while the network is down, so an outage does
 *     not hard-block a paying customer.
 *   • Only counts ever leave the machine — never a value, never the text.
 *
 * Gate reasons mirror the extension: no_key | invalid_key | over_limit | unreachable | ok
 *
 *   PII_SHIELD_KEY          workspace key (or ~/.pii-shield/key)
 *   PII_SHIELD_API          gateway origin (default https://piishield.ai)
 *   PII_SHIELD_TIMEOUT_MS   per-call timeout, default 3000 — a hook must never hang a session
 *   PII_SHIELD_REVALIDATE_MS  how often to re-check the plan, default 60000
 */
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import { createHmac } from "node:crypto";
import { STATE_DIR } from "./paths.mjs";
import { e2eEncrypt } from "./e2e-crypto.js";

/**
 * The same fingerprint the server would have computed, under the workspace's own blind key
 * (served by /api/ext/config). Identical to src/field-cipher.js blindIndex(), so a CLI
 * exposure dedupes and honours "Not PII" without us ever sending the value.
 */
const blindIndex = (value, blindKeyHex) =>
  createHmac("sha256", Buffer.from(blindKeyHex, "hex")).update(String(value).toLowerCase().trim()).digest("hex");

const API = (process.env.PII_SHIELD_API || "https://piishield.ai").replace(/\/$/, "");
const TIMEOUT = Number(process.env.PII_SHIELD_TIMEOUT_MS || 3000);
const REVALIDATE_MS = Number(process.env.PII_SHIELD_REVALIDATE_MS || 60_000);
const CACHE = path.join(STATE_DIR, "gate.json");

export const UPGRADE_URL = `${API}/my`;

/** Key from the environment, else ~/.pii-shield/key. */
export function readKey() {
  if (process.env.PII_SHIELD_KEY) return process.env.PII_SHIELD_KEY.trim();
  try {
    return fs.readFileSync(path.join(os.homedir(), ".pii-shield", "key"), "utf8").trim();
  } catch { return ""; }
}

function readCache() {
  try { return JSON.parse(fs.readFileSync(CACHE, "utf8")); } catch { return null; }
}

function writeCache(obj) {
  try {
    fs.mkdirSync(STATE_DIR, { recursive: true, mode: 0o700 });
    const tmp = `${CACHE}.${process.pid}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify(obj), { mode: 0o600 });
    fs.renameSync(tmp, CACHE);
  } catch { /* cache is an optimisation, never a requirement */ }
}

async function getJson(url, init) {
  const ac = new AbortController();
  const t = setTimeout(() => ac.abort(), TIMEOUT);
  try {
    const r = await fetch(url, { ...init, signal: ac.signal });
    return await r.json();
  } finally { clearTimeout(t); }
}

/**
 * Resolve the gate. Returns { open, reason, config?, plan?, used?, limit? }.
 * Hits the network at most once per REVALIDATE_MS; every hook invocation otherwise reads cache.
 */
export async function resolveGate() {
  const key = readKey();
  if (!key) return { open: false, reason: "no_key" };

  // Carry the plan picture through so callers can SHOW it (used/limit + pay-as-you-go credits),
  // not just act on the open/closed decision. The server already lets credits cover the monthly
  // overflow (overLimit stays false while credits remain), so these are for the user's eyes.
  const bal = (s) => ({ used: s.used, limit: s.limit, credits: s.credits ?? 0, remaining: s.remaining });
  const cached = readCache();
  const fresh = cached && cached.key === key && Date.now() - (cached.checkedAt || 0) < REVALIDATE_MS;
  if (fresh) {
    return cached.overLimit
      ? { open: false, reason: "over_limit", plan: cached.plan, ...bal(cached) }
      : { open: true, reason: "ok", config: cached.config, plan: cached.plan, e2e: !!cached.e2e, reveal_pubkey: cached.reveal_pubkey || null, blind_key: cached.blind_key || null, ...bal(cached) };
  }

  try {
    const d = await getJson(`${API}/api/ext/config?key=${encodeURIComponent(key)}`);
    if (!d || d.ok === false || d.error) {
      writeCache({ key, validated: false, checkedAt: Date.now() });
      return { open: false, reason: "invalid_key" };
    }
    const entry = { key, validated: true, config: d.config, plan: d.plan, used: d.used,
                    limit: d.limit, credits: d.credits ?? 0, remaining: d.remaining, overLimit: !!d.overLimit, e2e: !!d.e2e,
                    reveal_pubkey: d.reveal_pubkey || null, blind_key: d.blind_key || null, checkedAt: Date.now() };
    writeCache(entry);
    return d.overLimit
      ? { open: false, reason: "over_limit", plan: d.plan, ...bal(d) }
      : { open: true, reason: "ok", config: d.config, plan: d.plan, e2e: !!d.e2e, reveal_pubkey: d.reveal_pubkey || null, blind_key: d.blind_key || null, ...bal(d) };
  } catch {
    // Offline. A key we have confirmed before keeps working; one we never confirmed does not.
    if (cached && cached.key === key && cached.validated && !cached.overLimit) {
      return { open: true, reason: "ok", config: cached.config, plan: cached.plan, e2e: !!cached.e2e, reveal_pubkey: cached.reveal_pubkey || null, blind_key: cached.blind_key || null, ...bal(cached), stale: true };
    }
    return { open: false, reason: "unreachable" };
  }
}

/**
 * Report one billable redaction: counts only, never values. Mirrors /api/ext/usage.
 * Returns true when the server says we have now crossed the limit, so the caller can
 * close the gate immediately rather than waiting for the next revalidation.
 */
export async function meterUsage(count, counts, client = "plugin") {
  const key = readKey();
  if (!key) return false;
  try {
    const d = await getJson(`${API}/api/ext/usage`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ key, count, counts, source: "cli", client }),
    });
    if (d && d.overLimit) {
      const c = readCache() || { key };
      writeCache({ ...c, key, validated: true, overLimit: true, checkedAt: Date.now() });
      return true;
    }
  } catch { /* usage reporting is best-effort; protection already happened locally */ }
  return false;
}

/**
 * Report prevented exposures to the workspace Leak Audit.
 *
 * Nothing readable is transmitted. The masked preview is computed on this machine and then
 * encrypted with the workspace's RSA PUBLIC key (fetched with the gate config; the private
 * half never leaves the owner's browser). PII Shield's servers receive ciphertext they cannot
 * open, store it as-is, and the tenant decrypts it in their dashboard.
 *
 * We also send the blind index — the same HMAC the server would have computed, under the
 * workspace's own blind key — so the row still dedupes and still honours the workspace's
 * "Not PII" list. Without it, pre-encryption would silently kill both.
 *
 * Without a workspace public key there is nothing to encrypt to, so we send the type only.
 *   PII_SHIELD_LEAK_PREVIEW=0  send the type only, never an encrypted preview
 *   PII_SHIELD_LEAK_AUDIT=0    send nothing at all
 *
 * Best-effort: an audit row is never worth failing a redaction over.
 */
export async function reportLeaks(events, gate) {
  const key = readKey();
  if (!key || !events?.length || process.env.PII_SHIELD_LEAK_AUDIT === "0") return;

  const pub = gate?.reveal_pubkey || null;
  const blindKey = gate?.blind_key || null;
  const wantPreview = process.env.PII_SHIELD_LEAK_PREVIEW !== "0";

  const safe = events.map(({ type, value, preview, convo_ref }) => {
    const ev = { type, status: "prevented", convo_ref: convo_ref || null };
    // Fingerprint locally so the row dedupes and respects the workspace's "Not PII" list.
    if (blindKey && value) {
      try { ev.blind_idx = blindIndex(value, blindKey); } catch { /* no fingerprint, still no value */ }
    }
    // Only ever ciphertext. No `value`, no plaintext `masked_preview`. If encryption fails we
    // send the type alone — never the plaintext — but we say so, rather than degrade silently.
    if (pub && wantPreview && preview) {
      try { ev.cipher = e2eEncrypt(preview, pub); }
      catch (err) { process.stderr.write(`pii-shield: could not encrypt audit preview (${err?.message}); sending type only\n`); }
    }
    return ev;
  });

  try {
    await getJson(`${API}/api/ext/leaks`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ key, source: "cli", events: safe }),
    });
  } catch { /* the redaction already happened; the audit row is a bonus */ }
}

/** The message a user sees when the gate is shut. Explains why, and how to fix it. */
export function blockedMessage(gate, what = "This output") {
  const upgrade = `Upgrade or buy credits: ${UPGRADE_URL}`;
  switch (gate.reason) {
    case "no_key":
      return `[PII Shield] ${what} contains personal data and was withheld: no workspace key. ` +
             `Set PII_SHIELD_KEY (or write it to ~/.pii-shield/key). ` +
             `Your key is in your dashboard under Integration: ${API}/my — no account yet? ${API}/signup`;
    case "invalid_key":
      return `[PII Shield] ${what} contains personal data and was withheld: the workspace key is not valid. ${upgrade}`;
    case "over_limit":
      return `[PII Shield] ${what} contains personal data and was withheld: you have reached your ` +
             `${gate.plan ?? "plan"} limit (${gate.used ?? "?"}/${gate.limit ?? "?"} this month). ${upgrade}`;
    case "unreachable":
      return `[PII Shield] ${what} contains personal data and was withheld: could not reach PII Shield ` +
             `to verify your plan, and this key has never been validated on this machine.`;
    default:
      return `[PII Shield] ${what} contains personal data and was withheld. ${upgrade}`;
  }
}
