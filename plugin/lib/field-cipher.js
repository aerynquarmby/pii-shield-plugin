/**
 * Field-level crypto for the leak audit — AES-256-GCM + HMAC-SHA256 blind index,
 * plus masked previews. Same primitives proven in biokineticist-ai-invoice, but
 * PER-TENANT: every key is derived (HKDF) from a server master + the tenant id, so
 * one workspace can never decrypt another's, and a leaked value is only ever stored
 * as { masked_preview (safe), value_cipher (tenant-scoped), blind_idx (one-way) }.
 *
 * Threat model: PII Shield operators cannot read a leaked value without the master
 * secret; different tenants are cryptographically isolated. True client-held keys
 * (operator can't decrypt even with server access) are the P5 hardening — see
 * docs/leak-audit-and-document-redaction.md §B.4 / Part F.
 */
import { createCipheriv, createDecipheriv, createHmac, randomBytes, hkdfSync } from "node:crypto";

const ALGO = "aes-256-gcm";
const IV_LEN = 12;
const TAG_LEN = 16;

// Master secrets. Dedicated envs in prod; fall back to the existing ENCRYPTION_KEY /
// AUTH_SECRET so dev + tests work with zero new config. Distinct salts keep the
// encryption key and the blind-index key independent even from one master.
// An explicit `override` (raw secret string) is used by the rotation script to
// derive keys under an OLD or NEW master without touching process.env.
//
// In production there is no final fallback: the "dev-only-*" literals below are published in
// this repository, so deriving a real tenant's blind index from one would let anyone who reads
// the source recompute it. assertProdEnv() blocks boot first; this throws if it is bypassed.
//
// Only the "blind" master is live on the server. `encryptField`/`decryptField` derive from an
// operator-held master, which is exactly what the operator-blind design forbids, so the server
// never calls them — see the import comment in server.js. They survive for the rotation script
// and for reading rows written before the e2e migration.
function normalizeMaster(secret) {
  return /^[0-9a-fA-F]{64}$/.test(secret) ? Buffer.from(secret, "hex") : Buffer.from(String(secret), "utf8");
}
function master(kind, override) {
  if (override) return normalizeMaster(override);
  const dedicated = kind === "blind" ? process.env.LEAK_BLIND_MASTER : process.env.LEAK_ENC_MASTER;
  const env = dedicated || process.env.ENCRYPTION_KEY || process.env.AUTH_SECRET;
  if (env) return normalizeMaster(env);
  if (process.env.NODE_ENV === "production") {
    throw new Error(`No master secret for the leak ${kind} key: set LEAK_${kind === "blind" ? "BLIND" : "ENC"}_MASTER or ENCRYPTION_KEY`);
  }
  return normalizeMaster(kind === "blind" ? "dev-only-leak-blind-master" : "dev-only-leak-enc-master");
}

/** Derive a 32-byte key bound to (tenant, purpose), optionally under an explicit master. */
function deriveKey(kind, tenantId, override) {
  const salt = Buffer.from(kind === "blind" ? "pii-shield/leak/blind" : "pii-shield/leak/enc");
  const info = Buffer.from("tenant:" + String(tenantId || "global"));
  return Buffer.from(hkdfSync("sha256", master(kind, override), salt, info, 32));
}

/** Encrypt a value for a tenant. Returns base64(iv + ciphertext + authTag). */
export function encryptField(plaintext, tenantId, masterOverride) {
  if (typeof plaintext !== "string" || !plaintext) return "";
  const iv = randomBytes(IV_LEN);
  const cipher = createCipheriv(ALGO, deriveKey("enc", tenantId, masterOverride), iv, { authTagLength: TAG_LEN });
  const enc = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  return Buffer.concat([iv, enc, cipher.getAuthTag()]).toString("base64");
}

/** Decrypt a tenant value. Returns "" if it can't be decrypted (never throws). */
export function decryptField(ciphertext, tenantId, masterOverride) {
  if (!ciphertext || typeof ciphertext !== "string") return "";
  let buf;
  try { buf = Buffer.from(ciphertext, "base64"); } catch { return ""; }
  if (buf.length < IV_LEN + TAG_LEN + 1 || buf.toString("base64") !== ciphertext) return "";
  try {
    const iv = buf.subarray(0, IV_LEN);
    const tag = buf.subarray(buf.length - TAG_LEN);
    const enc = buf.subarray(IV_LEN, buf.length - TAG_LEN);
    const decipher = createDecipheriv(ALGO, deriveKey("enc", tenantId, masterOverride), iv, { authTagLength: TAG_LEN });
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(enc), decipher.final()]).toString("utf8");
  } catch { return ""; }
}

/** One-way HMAC fingerprint (normalised) — dedupe/"leaked again?" without decrypting. */
export function blindIndex(plaintext, tenantId, blindMasterOverride) {
  if (typeof plaintext !== "string" || !plaintext) return "";
  return createHmac("sha256", deriveKey("blind", tenantId, blindMasterOverride)).update(plaintext.toLowerCase().trim()).digest("hex");
}

/**
 * The per-tenant HMAC key behind `blindIndex`, as hex.
 *
 * Handed to a workspace's own clients (extension, CLI) so they can compute an IDENTICAL blind
 * index locally and never send us the value. It decrypts nothing; it is derived per tenant via
 * HKDF, so it reveals neither the master nor any other tenant's key. A holder of the workspace
 * key can use it to confirm a guess about their own workspace's data — which they could already
 * do, because they have the data.
 *
 * Without this, pre-encrypting on the client would silently kill dedupe and every tenant's
 * "Not PII" suppression, both of which key on the blind index.
 */
export function blindKeyHex(tenantId, blindMasterOverride) {
  return deriveKey("blind", tenantId, blindMasterOverride).toString("hex");
}

/** Does a value look like our base64 GCM ciphertext? Guard against storing plaintext. */
export function looksEncrypted(value) {
  if (typeof value !== "string" || value.length < 40 || !/^[A-Za-z0-9+/=]+$/.test(value)) return false;
  try { const b = Buffer.from(value, "base64"); return b.length >= IV_LEN + TAG_LEN + 1 && b.toString("base64") === value; }
  catch { return false; }
}

/**
 * Safe-to-store masked preview of a detected value, shaped by type. Never reversible.
 * jane@acme.com → j***@acme.com · 4111111111111111 → ****1111 · 192.168.0.1 → 192.*.*.*
 */
export function maskPreview(value, type) {
  const v = String(value == null ? "" : value).trim();
  if (!v) return "";
  const t = String(type || "").toUpperCase();
  const last = (s, n) => s.slice(-n);
  if (t === "EMAIL") {
    const [local, domain] = v.split("@");
    if (domain) return (local[0] || "") + "***@" + domain;
    return (v[0] || "") + "***";
  }
  if (t === "CREDIT_CARD" || t === "IBAN") { const d = v.replace(/\s|-/g, ""); return "****" + last(d, 4); }
  if (t === "SSN" || t === "SA_ID" || t === "ID") { const d = v.replace(/\D/g, ""); return "•••••" + last(d, 4); }
  if (t === "PHONE") { const d = v.replace(/\D/g, ""); return "•••‑•••‑" + last(d, 4); }
  if (t === "IPV4") return (v.split(".")[0] || "") + ".*.*.*";
  if (t === "PERSON" || t === "CUSTOM") {
    return v.split(/\s+/).map((w) => (w[0] || "") + "***").join(" ");
  }
  // default: first + last char visible
  if (v.length <= 2) return v[0] + "*";
  return v[0] + "***" + v[v.length - 1];
}
