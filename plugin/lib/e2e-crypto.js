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

/** Validate that a value is a usable RSA public JWK (used before saving). Returns bool. */
export function isValidPublicJwk(jwk) {
  try {
    const o = typeof jwk === "string" ? JSON.parse(jwk) : jwk;
    if (!o || o.kty !== "RSA" || !o.n || !o.e) return false;
    crypto.createPublicKey({ key: o, format: "jwk" }); // throws if malformed
    return true;
  } catch { return false; }
}
