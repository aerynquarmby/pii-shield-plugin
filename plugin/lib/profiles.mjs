/**
 * Detector profiles for coding agents.
 *
 * The engine's defaults are tuned for chat and documents, where an IP address is personal
 * data (it is, under GDPR) and a false positive costs nothing. In a coding agent the trade
 * inverts: IPV4/IPV6/MAC fire constantly on things that are not personal data at all —
 *
 *     "server listening on 0.0.0.0:8080"       -> [IPV4_1]:8080
 *     "curl http://127.0.0.1:3000/health"      -> http://[IPV4_1]:3000/health
 *     "upgraded from 1.2.3.4 to 1.2.3.5"       -> [IPV4_1] to [IPV4_2]
 *     "See RFC 5321 section 4.5.3.2"           -> section [IPV4_1]
 *     "const VERSION = \"10.2.14.1\""          -> "[IPV4_1]"
 *
 * — and a model that cannot see `127.0.0.1` gives wrong answers. A semver and an IPv4 address
 * are the same four dotted integers; no regex can separate them without context.
 *
 * So `code` (the default) drops those three. `strict` keeps everything, for anyone whose
 * threat model genuinely includes IP addresses and who accepts the noise.
 *
 * PII_SHIELD_PROFILE   code (default) | strict
 * PII_SHIELD_DETECTORS explicit comma list; overrides the profile entirely
 * PII_SHIELD_PERSON    1 to enable heuristic person-name detection
 * PII_SHIELD_CUSTOM_TERMS  comma list of literals to always mask
 * PII_SHIELD_ALLOW_TERMS   comma list of values to never mask (confirmed false positives)
 */

/** Network identifiers: pervasive in source, config, and logs; rarely the PII you meant. */
export const NOISY_IN_CODE = ["IPV4", "IPV6", "MAC"];

export const PROFILES = {
  code: (detectors) => {
    const out = { ...detectors };
    for (const k of NOISY_IN_CODE) if (k in out) out[k] = false;
    return out;
  },
  strict: (detectors) => ({ ...detectors }),
};

const list = (v) => String(v || "").split(",").map((s) => s.trim()).filter(Boolean);

/**
 * Build a RedactionSession config from the environment.
 * `base` is the engine's DEFAULT_CONFIG, passed in so this module never imports the engine
 * (the plugin vendors its own copy; bin/ uses src/).
 */
export function resolveConfig(base, env = process.env) {
  const cfg = { ...base, detectors: { ...base.detectors } };

  const explicit = list(env.PII_SHIELD_DETECTORS).map((s) => s.toUpperCase());
  if (explicit.length) {
    for (const k of Object.keys(cfg.detectors)) cfg.detectors[k] = false;
    for (const k of explicit) cfg.detectors[k] = true;
  } else {
    const profile = PROFILES[env.PII_SHIELD_PROFILE || "code"] || PROFILES.code;
    cfg.detectors = profile(cfg.detectors);
  }

  if (env.PII_SHIELD_PERSON === "1") cfg.detectors.PERSON = true;
  if (env.PII_SHIELD_CUSTOM_TERMS) cfg.customTerms = list(env.PII_SHIELD_CUSTOM_TERMS);
  if (env.PII_SHIELD_ALLOW_TERMS) cfg.allowTerms = list(env.PII_SHIELD_ALLOW_TERMS);
  return cfg;
}

/** Which detectors a given config will actually run. For diagnostics and docs. */
export const activeDetectors = (cfg) =>
  Object.entries(cfg.detectors).filter(([, on]) => on).map(([k]) => k);
