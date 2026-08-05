/**
 * PII Shield — secrets and credentials detection.
 *
 * Why this exists as its own module: until now the engine could find a crypto wallet ADDRESS
 * (public, harmless — it is the thing you hand out to receive money) and could not find the
 * PRIVATE KEY or the seed phrase that empties it. The same inversion ran through the whole
 * detector set: we masked the identifiers people are mildly embarrassed to leak and missed the
 * ones that cost money the same afternoon.
 *
 * When claude.ai's shared chats and published artifacts turned up in Google in July 2026, the
 * most-cited items in every writeup were API keys and wallet keys. See
 * docs/public-exposure-and-secrets.md.
 *
 * Precision strategy, in order of how much we trust it:
 *
 *   1. PROVIDER-PREFIXED tokens (`sk-ant-`, `AKIA`, `ghp_`, `xoxb-`) are effectively
 *      unforgeable by accident. A string starting `sk-ant-` followed by 20+ key characters is a
 *      key. These carry the highest confidence in the engine and need no surrounding context.
 *   2. STRUCTURAL forms — a PEM block, a JWT's three dot-separated base64url segments, a URI
 *      with an inline password. Rigid enough that prose does not imitate them.
 *   3. ASSIGNMENTS (`DB_PASSWORD=…`) are the loose end. The label is the evidence, so we require
 *      a credential-ish label AND a value that is not an obvious placeholder AND enough entropy
 *      to be a real secret. This is where false positives would come from, so it is gated hardest.
 *
 * Everything here returns spans in the same shape as detectLabeled()/detectPersons() so the
 * session's existing overlap, scoring and allowlist machinery applies unchanged.
 */
import { BIP39_WORDS } from "./bip39-words.js";

/** Shannon entropy in bits per character — distinguishes a real secret from "changeme". */
export function entropyPerChar(s) {
  if (!s) return 0;
  const freq = new Map();
  for (const ch of s) freq.set(ch, (freq.get(ch) || 0) + 1);
  let h = 0;
  for (const n of freq.values()) {
    const p = n / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

/**
 * Values that look like secrets but are documentation. Masking these trains people to ignore
 * the product, which is the failure mode that matters most for a detector like this.
 */
const PLACEHOLDER = /^(?:x{3,}|y{3,}|\.{3,}|-{3,}|_{3,}|\*{3,}|<[^>]*>|\{\{?[^}]*\}?\}|\$\{[^}]*\}|\$[A-Z_]+|%[A-Z_]+%)$/i;
const PLACEHOLDER_WORDS = new Set([
  "changeme", "change_me", "password", "passwd", "secret", "yourpassword", "yoursecret",
  "your_api_key", "your-api-key", "yourapikey", "apikey", "api_key", "token", "yourtoken",
  "example", "examplekey", "placeholder", "redacted", "removed", "hidden", "todo", "tbd",
  "none", "null", "nil", "undefined", "empty", "test", "testing", "dummy", "fake", "sample",
  "notarealkey", "insertkeyhere", "replaceme", "xxxxxxxx", "abc123", "123456", "password123",
]);

function isPlaceholder(v) {
  const t = String(v).trim();
  if (PLACEHOLDER.test(t)) return true;
  const bare = t.toLowerCase().replace(/[^a-z0-9_-]/g, "");
  if (PLACEHOLDER_WORDS.has(bare)) return true;
  if (/^(?:your|my|the|insert|enter|add|put)[_-]?/i.test(t)) return true;
  return false;
}

/**
 * Provider-issued credentials. Each prefix is registered/documented by its vendor, which is what
 * makes them safe to match without context. Ordered longest-prefix-first so `sk-ant-` wins over
 * the generic `sk-` branch when both could match.
 */
const PROVIDER_KEY = new RegExp(
  [
    "sk-ant-[A-Za-z0-9_-]{20,}",                       // Anthropic
    "sk-proj-[A-Za-z0-9_-]{20,}",                      // OpenAI project key
    "sk-[A-Za-z0-9]{32,}",                             // OpenAI classic / generic sk-
    "(?:AKIA|ASIA|AIDA|AROA|ANPA|AIPA)[0-9A-Z]{16}",   // AWS access key id
    "gh[pousr]_[A-Za-z0-9]{36,}",                      // GitHub PAT / OAuth / server / refresh
    "github_pat_[A-Za-z0-9_]{60,}",                    // GitHub fine-grained PAT
    "xox[baprs]-[A-Za-z0-9-]{10,}",                    // Slack
    "xapp-[0-9]-[A-Za-z0-9-]{10,}",                    // Slack app-level
    "[rs]k_(?:live|test)_[A-Za-z0-9]{20,}",            // Stripe
    "AIza[0-9A-Za-z_-]{35}",                           // Google API key
    "ya29\\.[0-9A-Za-z_-]{20,}",                       // Google OAuth access token
    "glpat-[A-Za-z0-9_-]{20,}",                        // GitLab PAT
    "npm_[A-Za-z0-9]{36}",                             // npm automation token
    "dop_v1_[a-f0-9]{64}",                             // DigitalOcean
    "shp(?:at|ca|pa|ss)_[a-fA-F0-9]{32}",              // Shopify
    "SG\\.[A-Za-z0-9_-]{22}\\.[A-Za-z0-9_-]{43}",      // SendGrid
    "hf_[A-Za-z0-9]{34,}",                             // Hugging Face
    "pplx-[A-Za-z0-9]{32,}",                           // Perplexity
    "gsk_[A-Za-z0-9]{40,}",                            // Groq
    "r8_[A-Za-z0-9]{37,}",                             // Replicate
  ].join("|"),
  "g",
);

/** A PEM private key block. Falls through to end-of-input when the END marker was not pasted. */
const PEM_PRIVATE_KEY = /-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY(?: BLOCK)?-----[\s\S]*?(?:-----END (?:[A-Z0-9 ]+ )?PRIVATE KEY(?: BLOCK)?-----|$)/g;

/** JSON Web Token — header.payload.signature, header always starts `eyJ` (base64 of `{"`). */
const JWT = /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*/g;

/** A URI carrying an inline password: postgres://user:pass@host, mongodb+srv://…, redis://… */
const CONNECTION_URI = /\b[a-z][a-z0-9+.\-]{2,}:\/\/[^\s:/@]+:[^\s:/@]+@[^\s/]+(?:\/[^\s]*)?/gi;

/** Bitcoin WIF private key — 5 (uncompressed) or K/L (compressed), base58, 51–52 chars. */
const WIF_PRIVATE_KEY = /\b[5KL][1-9A-HJ-NP-Za-km-z]{50,51}\b/g;

/**
 * A credential-shaped assignment. The LABEL is the evidence here, so it must genuinely name a
 * credential — `API_KEY`, `DB_PASSWORD`, `authToken`. Deliberately excludes bare `key`/`id`,
 * which label non-secret things constantly ("sort key", "row id").
 */
const SECRET_ASSIGNMENT =
  /\b([A-Za-z][A-Za-z0-9]*(?:[_.-][A-Za-z0-9]+)*?[_.-]?(?:api[_.-]?key|secret[_.-]?key|access[_.-]?key|private[_.-]?key|auth[_.-]?token|access[_.-]?token|refresh[_.-]?token|bearer[_.-]?token|client[_.-]?secret|api[_.-]?secret|password|passwd|pwd|passphrase|secret|credential|token))["'`]?\s*[:=]\s*(?:["'`])?([^\s"'`,;]{8,})(?:["'`])?/gi;

/** BIP-39 mnemonic lengths. Anything else is not a wallet phrase. */
const MNEMONIC_LENGTHS = new Set([12, 15, 18, 21, 24]);
/** 12–24 space-separated words, all 3–8 lowercase letters — the shape of a BIP-39 phrase. */
const MNEMONIC_CANDIDATE = /\b(?:[a-z]{3,8}[ \t\n]+){11,23}[a-z]{3,8}\b/g;

/**
 * Every word must be in the BIP-39 list, because that is precisely what a recovery phrase is.
 *
 * The previous rule guessed from shape — few stopwords, no repeated word — and got both directions
 * wrong. It blocked "make sure internal launch campaign doc also aligns with other docs strategy",
 * a real user's prompt, and because SEED_PHRASE scores 0.98 that was a hard block with no way past
 * it. And it silently MISSED genuine phrases: BIP-39 picks words with replacement, so about 3% of
 * real twelve-word phrases contain a repeat and were waved through by the no-repeats rule.
 *
 * Membership fixes both. Twelve of the commonest English words (you, have, this, that, they, then,
 * when, what, all, any, can, will) are in the list, so prose still cannot be ruled out on one word
 * alone — but needing twelve consecutive in-list words, unbroken by punctuation, effectively can
 * only happen on purpose.
 */
const MNEMONIC_CONTEXT = /\b(?:seed|mnemonic|recovery|wallet|passphrase|backup|restore|ledger|metamask|trezor)\b/i;

function looksLikeMnemonic(phrase, at = 0, text = "") {
  const words = phrase.trim().split(/\s+/);

  const lead = phrase.indexOf(phrase.trimStart());
  const hasContext = () =>
    MNEMONIC_CONTEXT.test(text.slice(Math.max(0, at - 60), at + phrase.length + 60));

  // The unambiguous case, which needs no corroboration: the whole run is a valid mnemonic length,
  // every word is in the wordlist, and no word repeats. That is what a pasted recovery phrase
  // looks like, and it is what the great majority of real ones look like.
  const allInList = words.every((w) => BIP39_WORDS.has(w));
  if (allInList && MNEMONIC_LENGTHS.has(words.length) && new Set(words).size === words.length) {
    return { offset: lead, value: words.join(" ") };
  }

  // Everything below is ambiguous enough that it needs the phrase to be introduced as a wallet
  // phrase. Two ambiguities, both of which look exactly like ordinary English:
  //
  //   - a REPEATED word. BIP-39 draws with replacement so ~3% of real phrases repeat, but prose
  //     repeats constantly.
  //   - a run that has to be WINDOWED. The candidate regex swallows neighbouring words, so
  //     "restore from <phrase>" arrives as fourteen and a real phrase was missed entirely. But
  //     hunting for a valid-length window inside a longer run also finds one in ordinary prose
  //     roughly ten times as often as the strict reading does — measured, not assumed.
  //
  // Requiring context costs the phrases nobody introduces, and buys back an order of magnitude of
  // false positives. A false positive here is a hard block with no way past it, so that is the
  // trade to make.
  if (!hasContext()) return false;

  let best = null, run = [], start = 0, cursor = lead;
  const flush = () => {
    if (run.length && (best === null || run.length > best.words.length)) best = { words: [...run], start };
  };
  for (const w of words) {
    if (BIP39_WORDS.has(w)) { if (!run.length) start = cursor; run.push(w); }
    else { flush(); run = []; }
    cursor += w.length + 1;
  }
  flush();
  if (!best || !MNEMONIC_LENGTHS.has(best.words.length)) return false;
  return { offset: best.start, value: best.words.join(" ") };
}

/**
 * Find every secret in `text`.
 *
 * Returns spans [{ start, end, type, value, via }] using six reporting types, because "you leaked
 * a credential" and "you leaked a wallet seed phrase" call for very different reactions:
 *
 *   API_KEY            provider-issued token
 *   PRIVATE_KEY        PEM block or crypto private key
 *   SEED_PHRASE        BIP-39 wallet recovery phrase
 *   JWT                bearer/session token
 *   CONNECTION_STRING  URI with an inline password
 *   SECRET             a credential-labelled assignment
 */
export function detectSecrets(text) {
  const spans = [];
  const push = (start, value, type, via) => {
    if (!value) return;
    spans.push({ start, end: start + value.length, type, value, via });
  };
  // A filter returns false to reject, true to accept the whole match, or {offset, value} to accept
  // a sub-span of it — which the mnemonic check needs, because the candidate regex swallows any
  // words that happen to sit either side of the phrase.
  const scan = (re, type, via, filter) => {
    re.lastIndex = 0;
    for (const m of text.matchAll(re)) {
      const verdict = filter ? filter(m[0], m.index, text) : true;
      if (!verdict) continue;
      if (verdict === true) push(m.index, m[0], type, via);
      else push(m.index + verdict.offset, verdict.value, type, via);
    }
  };

  scan(PEM_PRIVATE_KEY, "PRIVATE_KEY", "secret");
  scan(WIF_PRIVATE_KEY, "PRIVATE_KEY", "secret");
  scan(PROVIDER_KEY, "API_KEY", "secret");
  scan(JWT, "JWT", "secret");
  scan(CONNECTION_URI, "CONNECTION_STRING", "secret");
  scan(MNEMONIC_CANDIDATE, "SEED_PHRASE", "secret", looksLikeMnemonic);

  // Assignments: mask the VALUE only, never the label — masking `DB_PASSWORD` itself would
  // destroy the very config the user is asking the model about.
  SECRET_ASSIGNMENT.lastIndex = 0;
  for (const m of text.matchAll(SECRET_ASSIGNMENT)) {
    const value = m[2];
    if (!value || isPlaceholder(value)) continue;
    // A real secret is either long and varied, or short but clearly not a word. 2.2 bits/char
    // keeps "SuperSecret123!" and drops "aaaaaaaa".
    if (entropyPerChar(value) < 2.2) continue;
    const at = text.indexOf(value, m.index + m[1].length);
    if (at === -1) continue;
    push(at, value, "SECRET", "secret");
  }

  return spans;
}

/** The six types this module can produce — used by config, coverage UI and the dashboard. */
export const SECRET_TYPES = ["API_KEY", "PRIVATE_KEY", "SEED_PHRASE", "JWT", "CONNECTION_STRING", "SECRET"];
