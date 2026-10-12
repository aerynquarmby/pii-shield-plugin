/**
 * Keeping this session's token map, sealed, so a redacted file can be restored later.
 *
 * The plugin already holds a token map on disk — it has to, or redaction would not be stable
 * across a session (see session-store.mjs, which is honest about being a plaintext PII sidecar).
 * That sidecar is deleted at SessionEnd. This is the durable, SEALED counterpart: the same map,
 * encrypted here on the machine to keys the server does not hold, so a document redacted by a
 * coding agent can still be restored next week.
 *
 * Three properties, all decided on this machine:
 *
 *   Sealed locally. The server refuses anything without the "e2e:" prefix and has no code path
 *   that could produce one, so what it stores is bytes only this workspace can open.
 *
 *   Sealed to this device AND to the workspace recovery key, never to one shared key, so a stolen
 *   laptop costs this seat's maps rather than the company's.
 *
 *   Bound to "<tenantId>:<mapId>". A map that reaches the wrong workspace, or that gets applied to
 *   the wrong document, fails its auth tag and yields nothing — rather than yielding a different
 *   person's name, which is what a token numbered per session would otherwise do.
 *
 * Nothing here runs unless the workspace turned map-keeping on.
 */
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { e2eSeal } from "./e2e-crypto.js";
import { STATE_DIR as DIR } from "./paths.mjs";
import { readKey, API } from "./gate.mjs";

const DEVICE_FILE = path.join(DIR, "device-key.json");

/**
 * This machine's keypair, generated once and kept 0600 beside the session state.
 *
 * Unlike the browser we cannot hold a non-extractable key: a Node process reading its own file is
 * the only storage there is. The mitigation is the same one session-store.mjs already relies on —
 * 0700 directory, 0600 file, outside the repo — plus the fact that this key opens only maps sealed
 * to it, never another seat's and never another workspace's.
 */
async function deviceKey() {
  try {
    const held = JSON.parse(fs.readFileSync(DEVICE_FILE, "utf8"));
    if (held?.kid && held?.priv) return held;
  } catch { /* first run */ }

  const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  const pub = publicKey.export({ format: "jwk" });
  const priv = privateKey.export({ format: "jwk" });
  const key = readKey();
  if (!key) return null;
  const res = await fetch(`${API}/api/my/reveal-keys?key=${encodeURIComponent(key)}`, {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ publicKey: pub, label: "CLI plugin" }),
  }).then((r) => r.json()).catch(() => null);
  if (!res?.kid) return null;

  const rec = { kid: res.kid, pub: { kty: pub.kty, n: pub.n, e: pub.e }, priv };
  fs.mkdirSync(DIR, { recursive: true, mode: 0o700 });
  fs.writeFileSync(DEVICE_FILE, JSON.stringify(rec), { mode: 0o600 });
  return rec;
}

/** The recipients a map should be sealed to: every enrolled key, plus this device. */
function recipientsFrom(gate, device) {
  const to = [];
  for (const k of gate?.reveal_keys || []) if (k?.jwk?.n && k?.jwk?.e) to.push({ kid: String(k.kid), jwk: k.jwk });
  if (device?.pub && !to.some((k) => k.kid === device.kid)) to.push({ kid: device.kid, jwk: device.pub });
  return to;
}

/**
 * Seal this session's map and file it. Returns the id, or null when the workspace has not asked
 * for maps to be kept — which is the default and not an error.
 *
 * Never throws into a hook. A hook that fails is a hook that blocks somebody's work, and keeping a
 * map is a convenience; the redaction itself has already happened either way.
 */
export async function keepSessionMap(session, gate, { kind = "text", source = "cli" } = {}) {
  try {
    if (!gate?.keepTokenMaps || !gate?.tenant) return null;
    if (!session?.tokenToOriginal?.size) return null;
    const key = readKey();
    if (!key) return null;

    const device = await deviceKey();
    const to = recipientsFrom(gate, device);
    if (!to.length) return null;                     // nowhere to seal to: keep nothing rather than something readable

    const id = crypto.randomUUID();
    const map = {
      tokens: Object.fromEntries(session.tokenToOriginal),
      // The sidecar does not persist tokenSites, so a CLI-kept map restores the canonical value
      // rather than the exact surface form seen at each site. Recorded here rather than left to be
      // discovered: it is a fidelity limit of this surface, not of the format.
      sites: Object.fromEntries(session.tokenSites || []),
      config: { tokenPrefix: session.config?.tokenPrefix ?? "[", tokenSuffix: session.config?.tokenSuffix ?? "]" },
    };
    const aad = `${gate.tenant}:${id}`;
    const res = await fetch(`${API}/api/my/maps?key=${encodeURIComponent(key)}`, {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ id, map: e2eSeal(JSON.stringify(map), to, aad), kind, source, kids: to.map((k) => k.kid) }),
    }).then((r) => r.json()).catch(() => null);
    return res?.ok ? id : null;
  } catch { return null; }
}

export { deviceKey };
