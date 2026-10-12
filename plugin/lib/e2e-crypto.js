/**
 * Optional tenant-held end-to-end encryption for leak values.
 *
 * The tenant generates an RSA keypair IN THEIR BROWSER, uploads only the PUBLIC key.
 * The server encrypts leak values with it (hybrid: a random AES-256-GCM key encrypts the
 * value, RSA-OAEP wraps the AES key) and stores the result prefixed "e2e:". PII Shield
 * holds no private key, so it can NEVER decrypt these values at rest — reveal happens
 * client-side with the tenant's private key. Handles any value length (hybrid).
 *
 * Note: the raw value is transiently in server memory during ingest, then discarded; the
 * STORED data is not operator-decryptable. (Extension-side pre-encryption — so the raw
 * value never reaches the server at all — is a further hardening, see the design doc.)
 */
import crypto from "node:crypto";

export const E2E_PREFIX = "e2e:";

/** Encrypt `value` for a tenant using their RSA public key (JWK object or JSON string). */
export function e2eEncrypt(value, pubJwk) {
  const jwk = typeof pubJwk === "string" ? JSON.parse(pubJwk) : pubJwk;
  const pub = crypto.createPublicKey({ key: jwk, format: "jwk" });
  const aesKey = crypto.randomBytes(32);
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv("aes-256-gcm", aesKey, iv);
  const ct = Buffer.concat([c.update(String(value), "utf8"), c.final()]);
  const tag = c.getAuthTag();
  const wrapped = crypto.publicEncrypt({ key: pub, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: "sha256" }, aesKey);
  const blob = { k: wrapped.toString("base64"), iv: iv.toString("base64"), ct: ct.toString("base64"), tag: tag.toString("base64") };
  return E2E_PREFIX + Buffer.from(JSON.stringify(blob)).toString("base64");
}

export function isE2E(cipher) {
  return typeof cipher === "string" && cipher.startsWith(E2E_PREFIX);
}

/**
 * v2: seal for SEVERAL recipients, bound to where it belongs.
 *
 * Two problems v1 cannot solve, both of which a token map has.
 *
 * Recipients. A map has to open for the seat that produced it AND for the owner's recovery key,
 * and those two must not share a private key — one workspace key for everything means a single
 * stolen laptop exposes every map the company has. The AES key is cheap to wrap more than once
 * (256 bytes per recipient), so wrap it per recipient and leave the body alone.
 *
 * Binding. `aad` is authenticated but not encrypted: change it and the auth tag stops verifying.
 * Callers pass "<tenantId>:<eventId>", so a blob that reaches the wrong tenant, or a map applied
 * to the wrong redaction, decrypts to NOTHING instead of to somebody else's name. That is not
 * paranoia: tokenFor() in redact.js numbers tokens from a per-session counter, so `[EMAIL_1]` is
 * a different person in every document and a mis-applied map fails silently and plausibly. This
 * turns cross-contamination from a code-review property into a mathematical one.
 *
 * The server must never call this. It is exported for the CLI plugin and the tests, which are
 * clients; see the import comment in server.js.
 */
export function e2eSeal(value, recipients, aad) {
  if (!aad) throw new Error("e2eSeal: aad is required — a sealed value must be bound to its tenant and event");
  const list = (Array.isArray(recipients) ? recipients : [recipients]).filter(Boolean);
  if (!list.length) throw new Error("e2eSeal: at least one recipient is required");
  const aesKey = crypto.randomBytes(32);
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv("aes-256-gcm", aesKey, iv);
  c.setAAD(Buffer.from(String(aad), "utf8"));
  const ct = Buffer.concat([c.update(String(value), "utf8"), c.final()]);
  const tag = c.getAuthTag();
  const k = list.map((r) => {
    const jwk = typeof r.jwk === "string" ? JSON.parse(r.jwk) : r.jwk;
    const pub = crypto.createPublicKey({ key: jwk, format: "jwk" });
    const w = crypto.publicEncrypt({ key: pub, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: "sha256" }, aesKey);
    return { kid: String(r.kid), w: w.toString("base64") };
  });
  const blob = { v: 2, k, iv: iv.toString("base64"), ct: ct.toString("base64"), tag: tag.toString("base64") };
  return E2E_PREFIX + Buffer.from(JSON.stringify(blob)).toString("base64");
}

/** Parse the envelope. Throws on anything that is not one, so callers cannot half-succeed. */
function parseEnvelope(cipher) {
  if (!isE2E(cipher)) throw new Error("not an e2e ciphertext");
  return JSON.parse(Buffer.from(cipher.slice(E2E_PREFIX.length), "base64").toString("utf8"));
}

/** Which recipients can open this, so a client knows before it tries. [] for a v1 blob. */
export function e2eKids(cipher) {
  const blob = parseEnvelope(cipher);
  return Array.isArray(blob.k) ? blob.k.map((r) => r.kid) : [];
}

/**
 * Open a sealed value with one recipient's private key. Throws — never returns a wrong value —
 * when the key, the recipient or the binding does not match. Reads v1 blobs too, so leak rows
 * written before this existed still open (they have a single wrapped key and no binding).
 */
export function e2eOpen(cipher, privJwk, kid, aad) {
  const blob = parseEnvelope(cipher);
  const jwk = typeof privJwk === "string" ? JSON.parse(privJwk) : privJwk;
  const priv = crypto.createPrivateKey({ key: jwk, format: "jwk" });
  let wrapped;
  if (Array.isArray(blob.k)) {
    const slot = kid ? blob.k.find((r) => r.kid === String(kid)) : blob.k[0];
    if (!slot) throw new Error(`e2eOpen: nothing sealed for recipient ${kid}`);
    wrapped = Buffer.from(slot.w, "base64");
  } else {
    wrapped = Buffer.from(blob.k, "base64"); // v1
  }
  const aesKey = crypto.privateDecrypt({ key: priv, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: "sha256" }, wrapped);
  const d = crypto.createDecipheriv("aes-256-gcm", aesKey, Buffer.from(blob.iv, "base64"));
  if (aad) d.setAAD(Buffer.from(String(aad), "utf8"));
  d.setAuthTag(Buffer.from(blob.tag, "base64"));
  return Buffer.concat([d.update(Buffer.from(blob.ct, "base64")), d.final()]).toString("utf8");
}

/** Validate that a value is a usable RSA public JWK (used before saving). Returns bool. */
export function isValidPublicJwk(jwk) {
  try {
    const o = typeof jwk === "string" ? JSON.parse(jwk) : jwk;
    if (!o || o.kty !== "RSA" || !o.n || !o.e) return false;
    crypto.createPublicKey({ key: o, format: "jwk" }); // throws if malformed
    return true;
  } catch { return false; }
}
