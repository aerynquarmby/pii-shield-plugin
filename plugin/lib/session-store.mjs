/**
 * Session-scoped token map, persisted across hook invocations.
 *
 * A hook is a fresh process every time, but redaction must be stable within a session:
 * the same email has to map to [EMAIL_1] on turn 1 and turn 40, and PreToolUse has to be
 * able to turn [EMAIL_1] back into the real address before it lands on disk.
 *
 * That means the token -> original map has to live somewhere. It is, unavoidably, a
 * plaintext PII sidecar. So: 0700 dir, 0600 file, outside the repo, atomic rename, deleted
 * on SessionEnd, and swept after PII_SHIELD_TTL_HOURS in case SessionEnd never fires.
 *
 * Override the location with PII_SHIELD_STATE_DIR.
 */
import fs from "node:fs";
import path from "node:path";
import { RedactionSession, DEFAULT_CONFIG } from "./redact.js";
import { resolveConfig } from "./profiles.mjs";
import { STATE_DIR as DIR } from "./paths.mjs";

const TTL_MS = Number(process.env.PII_SHIELD_TTL_HOURS || 24) * 3600_000;

/** Session ids are uuids, but never trust an id straight into a path. */
const safeId = (id) => String(id || "no-session").replace(/[^A-Za-z0-9_-]/g, "_").slice(0, 128);

const fileFor = (sessionId) => path.join(DIR, `${safeId(sessionId)}.json`);

/** Detector set for this session. Defaults to the `code` profile — see profiles.mjs. */
export const configFromEnv = () => resolveConfig(DEFAULT_CONFIG);

/**
 * Workspace coverage rules win when a key is present — same as the extension, where
 * `d.config` from /api/ext/config overrides the local defaults. The `code` profile is then
 * applied on top, because IPV4/IPV6/MAC wreck a coding agent even when the workspace wants
 * them (a semver and an IP are the same four dotted integers). `PII_SHIELD_PROFILE=strict`
 * opts back in.
 */
export const configFromGate = (gate) =>
  resolveConfig({ ...DEFAULT_CONFIG, ...(gate?.config || {}),
                  detectors: { ...DEFAULT_CONFIG.detectors, ...(gate?.config?.detectors || {}) } });

/** Delete state files older than the TTL. Cheap, best-effort, never throws. */
function sweep() {
  try {
    const now = Date.now();
    for (const f of fs.readdirSync(DIR)) {
      if (f === "gate.json") continue; // billing cache: losing it hard-blocks an offline paid user
      const p = path.join(DIR, f);
      try {
        if (now - fs.statSync(p).mtimeMs > TTL_MS) fs.rmSync(p, { force: true });
      } catch { /* racing with another hook; fine */ }
    }
  } catch { /* dir absent */ }
}

/** Rebuild a RedactionSession with the token map it had last time this session ran. */
export function load(sessionId, config = configFromEnv()) {
  sweep();
  const s = new RedactionSession(config);
  try {
    const raw = JSON.parse(fs.readFileSync(fileFor(sessionId), "utf8"));
    s.counters = raw.counters || {};
    s.counts = raw.counts || {};
    s.total = raw.total || 0;
    s.byKey = new Map(Object.entries(raw.byKey || {}));
    s.tokenToOriginal = new Map(Object.entries(raw.tokenToOriginal || {}));
  } catch (err) {
    // ENOENT is the normal first call of a session: no state file yet, nothing to restore.
    // Any other error (corrupt JSON, unreadable file, a state dir that moved out from under us)
    // leaves an EMPTY token map, so rehydrate silently writes tokens to disk unrestored. This
    // file's contract is "fail open, but loudly" — degrade, but never in silence.
    if (err && err.code !== "ENOENT") {
      process.stderr.write(
        `pii-shield: could not load session state (${err.message ?? err}); ` +
        `redaction tokens will not be restored on this call\n`);
    }
  }
  return s;
}

export function save(sessionId, s) {
  fs.mkdirSync(DIR, { recursive: true, mode: 0o700 });
  try { fs.chmodSync(DIR, 0o700); } catch { /* not ours */ }
  const target = fileFor(sessionId);
  const tmp = `${target}.${process.pid}.tmp`;
  const payload = {
    counters: s.counters,
    counts: s.counts,
    total: s.total,
    byKey: Object.fromEntries(s.byKey),
    tokenToOriginal: Object.fromEntries(s.tokenToOriginal),
  };
  fs.writeFileSync(tmp, JSON.stringify(payload), { mode: 0o600 });
  fs.renameSync(tmp, target);
  try { fs.chmodSync(target, 0o600); } catch { /* best effort */ }
}

export function destroy(sessionId) {
  try { fs.rmSync(fileFor(sessionId), { force: true }); } catch { /* already gone */ }
}

export { fileFor as stateFileFor };
