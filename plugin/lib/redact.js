/**
 * PII Shield — redaction engine.
 *
 * Generalises the session-scoped pseudonym pattern from futurefund-app,
 * sigma-v3-dashboard (HyperSend) and biokineticist-ai-invoice into a
 * standalone engine that redacts FREE TEXT (Anthropic Messages API bodies),
 * not just known object fields.
 *
 * Design:
 *  - Each request gets a RedactionSession. Every unique sensitive value is
 *    assigned a STABLE token ([EMAIL_1], [PERSON_2]) for the life of that
 *    request, so the model reasons over consistent identities.
 *  - The session holds token -> original in memory only for the duration of
 *    the request, so the response can be RE-HYDRATED before the caller sees it.
 *  - Raw PII is NEVER persisted by this module. Audit logs store type counts only.
 *    (A workspace can opt into keeping the token map so a redacted document can be restored
 *    later. That map is sealed by the CLIENT to keys the server does not hold, and never by
 *    anything here — see src/e2e-crypto.js e2eSeal and the token_maps ingress in server.js.)
 */

import { FIRST_NAMES, NAME_STOPWORDS, HONORIFICS, PLACE_PREFIXES, isGivenName, isSurname, isWordSurname } from "./gazetteer.js";
import { scoreMatch } from "./scoring.js";
import { detectSecrets, SECRET_TYPES } from "./secrets.js";

export { detectSecrets, SECRET_TYPES };

/**
 * How each built-in detector PROVES a match — the input to evidence-based scoring.
 *   checksum   — a real check ran and passed (Luhn, Verhoeff, NINO prefix).
 *   structural — a format too rigid to hit by accident (email, IBAN, MAC, 0x-address).
 *   shape      — it merely looks right (a phone shape, a VIN shape, a street shape).
 * A checksum-backed card and a bare 10-digit run are NOT the same claim; this is what lets the
 * scorer say so, instead of stamping every match of a type with one static number.
 */
const VIA_BY_TYPE = {
  CREDIT_CARD: "checksum", SA_ID: "checksum", AADHAAR: "checksum", NINO_UK: "checksum",
  EMAIL: "structural", IPV6: "structural", MAC: "structural", ETH_ADDRESS: "structural",
  BTC_ADDRESS: "structural", PAN_INDIA: "structural", IBAN: "structural",
  PHONE: "shape", VIN: "shape", STREET_ADDRESS: "shape", IPV4: "shape", SSN: "shape",
};

// ------------------------------ Detectors ------------------------------

/** Luhn check — used to keep card / SA-ID detection high-precision. */
function luhnValid(digits) {
  let sum = 0;
  let alt = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let n = digits.charCodeAt(i) - 48;
    if (n < 0 || n > 9) return false;
    if (alt) {
      n *= 2;
      if (n > 9) n -= 9;
    }
    sum += n;
    alt = !alt;
  }
  return sum % 10 === 0;
}

/** Verhoeff checksum — validates Indian Aadhaar numbers (keeps AADHAAR high-precision). */
const VERHOEFF_D = [[0,1,2,3,4,5,6,7,8,9],[1,2,3,4,0,6,7,8,9,5],[2,3,4,0,1,7,8,9,5,6],[3,4,0,1,2,8,9,5,6,7],[4,0,1,2,3,9,5,6,7,8],[5,9,8,7,6,0,4,3,2,1],[6,5,9,8,7,1,0,4,3,2],[7,6,5,9,8,2,1,0,4,3],[8,7,6,5,9,3,2,1,0,4],[9,8,7,6,5,4,3,2,1,0]];
const VERHOEFF_P = [[0,1,2,3,4,5,6,7,8,9],[1,5,7,6,2,8,3,0,9,4],[5,8,0,3,7,9,6,1,4,2],[8,9,1,6,0,4,3,5,2,7],[9,4,5,3,1,2,6,8,7,0],[4,2,8,6,5,7,3,9,0,1],[2,7,9,3,8,0,6,4,1,5],[7,0,4,6,9,1,3,2,5,8]];
function verhoeffValid(num) {
  if (!/^\d{12}$/.test(num)) return false;
  let c = 0;
  const digits = num.split("").reverse().map(Number);
  for (let i = 0; i < digits.length; i++) c = VERHOEFF_D[c][VERHOEFF_P[i % 8][digits[i]]];
  return c === 0;
}

/**
 * Built-in detectors. Each: { type, re, validate? }.
 * `validate(match)` returns true to keep a match (used for Luhn gating).
 * Order matters only for reporting; overlaps are resolved by span, longest-first.
 */
export const BUILTIN_DETECTORS = {
  EMAIL: {
    type: "EMAIL",
    // A single optional space either side of the @, and around the dots in the domain.
    // The case-insensitive flag is deliberately GONE. With it, `[a-z]{2,}` after a spaced dot also
    // matched "Referred", so "marcus.delacroix@example.com. Referred" was stored, whole, as the
    // address — which is why a second sighting in notes minted a NEW token instead of reusing the
    // first, and why sending that token back would have queried a malformed address. A domain
    // broken across a line wrap is lowercase; a sentence carrying on is capitalised. That is the
    // whole signal, and it only works if case is respected.
    re: /[\p{L}0-9._%+\-]+[  ]?@[  ]?[\p{L}0-9\-]+(?:[  ][\p{Ll}0-9\-]+)?(?:(?:\.[\p{L}0-9\-]+|[  ]\.[  ]?[\p{Ll}0-9\-]+|\.[  ][\p{Ll}0-9\-]+)(?:[  ][\p{Ll}0-9\-]+)?)*(?:\.[\p{L}]{2,}|[  ]\.[  ]?[\p{Ll}]{2,}|\.[  ][\p{Ll}]{2,})/gu,
  },
  CREDIT_CARD: {
    type: "CREDIT_CARD",
    re: /(?<![\d])\d(?:[ \-]?\d){12,18}(?![\d])/g,
    validate: (m) => {
      const d = m.replace(/[ \-]/g, "");
      return d.length >= 13 && d.length <= 19 && luhnValid(d);
    },
  },
  SA_ID: {
    // South African 13-digit ID: YYMMDD + sequence + citizenship + Luhn check digit.
    //
    // Written by hand it is almost never 13 bare digits — the official grouping is 6 4 2 1, and
    // people use spaces, hyphens or slashes at those joins. Those forms WERE still masked, but by
    // the credit-card detector, which is worse than it sounds: a workspace with cards switched off
    // and SA ID switched on would have leaked every one of them. Separators are permitted only at
    // the four real group boundaries, so this cannot wander across two unrelated numbers.
    type: "SA_ID",
    re: /(?<!\w)\d{6}[ \u00a0.\-/]?\d{4}[ \u00a0.\-/]?\d{2}[ \u00a0.\-/]?\d(?!\w)/g,
    validate: (m) => {
      const d = m.replace(/\D/g, "");
      if (d.length !== 13) return false;
      // The checksum is deliberately NOT required. A real contract carried
      // "Jennifer Testcase (9008130035084)": valid date, valid citizenship digit, failed Luhn —
      // and it went unmasked. A mistyped or synthetic ID still identifies a person. The
      // difference is carried by CONFIDENCE instead, so a checksum-valid ID stays "high" and
      // one that fails is reported at medium for the reviewer to judge.
      const mm = +d.slice(2, 4);
      const dd = +d.slice(4, 6);
      if (!(mm >= 1 && mm <= 12 && dd >= 1 && dd <= 31)) return false;
      // Recorded on the detector so scoring can grade the two cases differently. `validate` cannot
      // see the match object, so this is the narrowest channel available.
      SA_ID_LAST_LUHN = luhnValid(d);
      // Position 11 is citizenship: 0 = citizen, 1 = permanent resident. Nothing else is issued.
      // Loosening the shape widened what reaches this check, so tighten the check to match: this
      // rejects four fifths of the random 13-digit runs that happen to pass Luhn and a date.
      return d[10] === "0" || d[10] === "1";
    },
  },
  SSN: {
    type: "SSN",
    re: /(?<![A-Za-z0-9])\d{3}-\d{2}-\d{4}(?![A-Za-z0-9])/g,
  },
  PHONE: {
    // The many shapes people write numbers in: +CC, (area), 2–5-digit groups on
    // space/dash/dot (UK 4-4-4, India 5-5, US/SA 3-3-4), or a bare 9–11-digit run.
    // validate() gates out years/versions/quantities so we don't over-mask.
    type: "PHONE",
    // Groups run 2–6 digits (UK mobile has a 6-digit tail: 07700 900123). The bare-digit branch
    // is split: an international +number may run to 14 digits, but a bare run stays capped at 11
    // so 12–15-digit account/ledger reference numbers aren't swept up (validate() waves through
    // any bare run of ≥10 digits, so the cap is the only guard there).
    re: /(?<!\w)(?:\+\d{1,3}[ \u00a0\-.]?)?(?:\(\d{1,4}\)[ \u00a0\-.]?|\d{1,4}[ \u00a0\-.])?\d{2,6}(?:[ \u00a0\-.]\d{2,6}){1,4}(?!\w)|(?<![\w.])\+\d{1,3}(?:[ \u00a0\-.]?\d{1,9}){1,4}(?!\w)|(?<![\w.])\+\d{9,14}(?!\w)|(?<![\w.])\d{9,11}(?!\w)/g,
    validate: (m) => {
      const t = m.trim();
      const d = m.replace(/\D/g, "");
      if (d.length < 7 || d.length > 15) return false;
      // Reject dates (ISO YYYY-MM-DD and D/M/Y forms) — a dash/slash doesn't make it a phone.
      if (/^\d{4}[-/.]\d{1,2}[-/.]\d{1,2}$/.test(t) || /^\d{1,2}[-/.]\d{1,2}[-/.]\d{2,4}$/.test(t)) return false;
      const groups = t.split(/[ \-.]+/);
      if (groups.length > 1 && groups.every((g) => g.length === 4)) return false; // "2020 2021 2022"
      // Strong phone signals: intl +, area parens, or a local number starting 0.
      if (/^\+/.test(t) || /[()]/.test(t) || /^0/.test(d)) return true;
      // Otherwise-formatted (separators present, date already excluded) → phone.
      if (/[ \-.]/.test(t)) return true;
      // Bare unformatted digits need 10+ so 9-digit reference/ID numbers aren't over-masked.
      return d.length >= 10;
    },
  },
  IPV4: {
    type: "IPV4",
    re: /(?<![A-Za-z0-9])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?![A-Za-z0-9])/g,
  },
  IBAN: {
    // Printed in 4-char groups (DE89 3704 0044 …) or contiguous (GB33BUKB…).
    type: "IBAN",
    re: /(?<![A-Z0-9])[A-Z]{2}\d{2}(?: [A-Z0-9]{4}){2,7}(?: [A-Z0-9]{1,4})?(?![A-Z0-9])|(?<![A-Z0-9])[A-Z]{2}\d{2}[A-Z0-9]{11,30}(?![A-Z0-9])/g,
    // mod-97 (ISO 7064) is run, but as EVIDENCE rather than as a gate — the same decision already
    // taken for SA_ID. An IBAN-shaped string whose check digits do not add up is still almost
    // certainly a bank account: someone mistyped it, or it came from a test system. Refusing to
    // mask it trades a real leak for a tidy-looking rejection, so instead it is masked and reported
    // at lower confidence, and the reviewer is told which of the two it was.
    validate: (m) => {
      const t = m.replace(/[\s\-]/g, "").toUpperCase();
      if (t.length < 15 || t.length > 34) return false;
      IBAN_LAST_MOD97 = false;
      if (/^[A-Z]{2}\d{2}[A-Z0-9]+$/.test(t)) {
        const rot = t.slice(4) + t.slice(0, 4);
        let rem = 0;
        for (const ch of rot) {
          const v = ch >= "A" && ch <= "Z" ? String(ch.charCodeAt(0) - 55) : ch;
          for (const d of v) rem = (rem * 10 + Number(d)) % 97;
        }
        IBAN_LAST_MOD97 = rem === 1;
      }
      return true;
    },

  },
  // ---- Extended identifier coverage (all high-precision / checksum- or format-gated) ----
  IPV6: {
    type: "IPV6",
    // The COMPRESSED form (2001:db8:85a3::8a2e:370:7334) must come first. Alternation is ordered
    // and both branches can start at the same character, so with the uncompressed branch leading
    // it won by matching the short prefix "2001:db8:85a3" — which then failed validate() for
    // having too few colons, and the whole address went undetected.
    re: /\b(?:[A-F0-9]{1,4}:){1,7}:(?:[A-F0-9]{1,4}:?){0,6}[A-F0-9]{0,4}\b|\b(?:[A-F0-9]{1,4}:){2,7}[A-F0-9]{1,4}\b/gi,
    validate: (m) => {
      if (!m.includes(":")) return false;
      const colons = (m.match(/:/g) || []).length;
      if (colons <= 2 && /^\d{1,2}(?::\d{1,2}){1,2}$/.test(m)) return false; // clock time 10:30:45
      return m.includes("::") || colons >= 4; // compressed form, or a full-length address
    },
  },
  MAC: {
    type: "MAC",
    re: /\b(?:[0-9A-F]{2}[:-]){5}[0-9A-F]{2}\b/gi,
  },
  VIN: {
    // 17 chars, no I/O/Q. The shape alone is not evidence: see vinTier for what is. The second
    // lookbehind keeps an AWS resource id (i-0a1b…, vol-049d…, ami-0c55…) out — 17 hex characters
    // after a short lowercase prefix, and the commonest false VIN there is in technical text.
    type: "VIN",
    re: /(?<![A-Za-z0-9])(?<![a-z]-)[A-HJ-NPR-Z0-9]{17}(?![A-Za-z0-9])/gi,
    validate: (m) => { VIN_LAST_TIER = vinTier(m); return VIN_LAST_TIER !== null; },
  },
  PAN_INDIA: {
    // Indian Permanent Account Number: AAAAA1234A (5 letters, 4 digits, 1 letter).
    type: "PAN_INDIA",
    re: /(?<![A-Za-z0-9])[A-Z]{5}[0-9]{4}[A-Z](?![A-Za-z0-9])/g,
  },
  NINO_UK: {
    // UK National Insurance Number: two prefix letters (restricted set), 6 digits, a suffix A–D.
    type: "NINO_UK",
    re: /(?<![A-Za-z0-9])[ABCEGHJ-PRSTW-Z][ABCEGHJ-NPRSTW-Z] ?\d{2} ?\d{2} ?\d{2} ?[A-D](?![A-Za-z0-9])/g,
    validate: (m) => { const s = m.replace(/\s/g, "").toUpperCase(); return !/^(BG|GB|NK|KN|TN|NT|ZZ)/.test(s); },
  },
  AADHAAR: {
    // Indian Aadhaar: 12 digits (never starts 0/1), printed in 4-4-4 groups, Verhoeff-checked.
    // The lookbehind/lookahead stop it matching the FIRST 12 digits of a longer space-grouped
    // number — critically a 16-digit credit card written "3505 4121 6080 5306", where matching
    // "3505 4121 6080" and (since AADHAAR outranks CREDIT_CARD) winning the overlap would mask 12
    // digits and LEAK THE LAST 4. A separator+digit on either side means it is part of a longer run.
    type: "AADHAAR",
    re: /(?<![\d][ \-.])\b[2-9]\d{3} \d{4} \d{4}\b(?![ \-.]?\d)/g,
    validate: (m) => {
      // Three 4-digit groups that all read as years ("2018 2016 1999") are a year list, not an
      // Aadhaar — reject before Verhoeff (which ~10% of random triples pass by chance).
      if (m.split(" ").every((g) => +g >= 1900 && +g <= 2099)) return false;
      return verhoeffValid(m.replace(/\D/g, ""));
    },
  },
  ETH_ADDRESS: {
    type: "ETH_ADDRESS",
    re: /(?<![A-Za-z0-9])0x[a-fA-F0-9]{40}(?![A-Za-z0-9])/g,
  },
  BTC_ADDRESS: {
    // Legacy (1/3…, base58) or bech32 (bc1…). Length-gated; base58 excludes 0/O/I/l.
    type: "BTC_ADDRESS",
    re: /(?<![A-Za-z0-9])(?:bc1[a-z0-9]{25,59}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})(?![A-Za-z0-9])/g,
  },
  PO_BOX: {
    // "P.O. Box 5512, Sandton, 2196". The street detector wants a number, a named street and a
    // street type; a PO box has none of them, so it sailed through untouched.
    type: "STREET_ADDRESS",
    re: /\b(?:P\.?\s?O\.?\s?Box|Post(?:al)? Box|Private Bag(?: X)?)\s*[:#]?\s*[A-Za-z0-9\-]{1,10}(?:,? +(?:\p{Lu}[\p{L}'.\-]+)(?: +\p{Lu}[\p{L}'.\-]+){0,2})?(?:,? +\d{4,5})?/giu,
  },
  GPS: {
    // A decimal coordinate pair locates a home to within metres. Bounded to real latitude and
    // longitude ranges, and both parts must carry decimals, so "3, 4" and version numbers are safe.
    type: "GPS",
    re: /(?<![\d.])-?(?:[0-8]?\d|90)\.\d{3,8}\s*,\s*-?(?:1[0-7]\d|[0-9]?\d)\.\d{3,8}(?![\d.])/g,
  },
  STREET_ADDRESS: {
    // Street number + name + a street-type suffix (Street/Ave/Rd/…). The suffix + a named
    // street between it and the number keep precision high (so "Section 3 Road map" won't hit).
    type: "STREET_ADDRESS",
    // The tail matters as much as the street line. Masking only "12 Kloof Street" and leaving
    // ", Cape Town, 7700" is not protection: a postcode plus a surname re-identifies, and the
    // surname is elsewhere in the same record. So an immediately following locality and/or postal
    // code is taken WITH the address — but only when it trails this address directly, so a city
    // mentioned on its own ("the role is based in Cape Town") is untouched.
    //
    // Each locality word ends `\b(?!\d)`, which is doing more work than it looks. Without it the
    // word matcher happily takes the "NW" out of "NW1 6XE" as if it were a second town, which
    // then leaves no separator for the postcode branch to match against — so the address was
    // masked and "1 6XE" was left sitting beside it in the clear. The `\b` also stops the engine
    // backtracking to a shorter prefix ("N") to satisfy the lookahead, which is the trap in
    // writing this as a bare `(?!\d)`.
    re: /\b\d{1,6}[A-Za-z]?\s+(?:[A-Z][A-Za-z'.\-]+\s+){1,4}(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct|Place|Pl|Way|Terrace|Ter|Close|Crescent|Cres|Square|Sq|Parkway|Pkwy|Highway|Hwy|Trail|Circle|Cir|Loop|Row|Walk)\b\.?(?:,? +(?:[A-Z][A-Za-z'.\-]+\b(?!\d))(?: +[A-Z][A-Za-z'.\-]+\b(?!\d)){0,2})?(?:,? +(?:[A-Z]{1,2}\d[A-Z\d]? *\d[A-Z]{2}|\d{4,5}(?:-\d{4})?))?/g,
  },
};

/**
 * How each detection is PROVEN — drives the confidence score and the human-readable
 * rationale shown in review/triage UIs. Confidence is not a guess: it reflects whether the
 * match was checksum-validated, structurally unambiguous, or heuristic.
 *   high (0.95)   — checksum or an unmistakable format
 *   medium (0.70) — a structural pattern that real text can occasionally imitate
 * Every surface (gateway, documents, extension, MCP, CLI) reads from this one table.
 */
export const CONFIDENCE = {
  EMAIL:          { level: "high",   score: 0.98, reason: "Email address format" },
  CREDIT_CARD:    { level: "high",   score: 0.98, reason: "Luhn-valid card number" },
  SA_ID:          { level: "high",   score: 0.97, reason: "Luhn-valid 13-digit South African ID with a valid date" },
  SA_ID_WEAK:     { level: "medium", score: 0.72, reason: "13-digit South African ID shape and a valid date, but the check digit does not match - mistyped or synthetic" },
  AADHAAR:        { level: "high",   score: 0.97, reason: "Verhoeff-checked Aadhaar number" },
  SSN:            { level: "high",   score: 0.93, reason: "US Social Security number format" },
  IBAN:           { level: "high",   score: 0.95, reason: "IBAN country + check-digit structure" },
  IPV4:           { level: "high",   score: 0.93, reason: "IPv4 address" },
  IPV6:           { level: "high",   score: 0.93, reason: "IPv6 address" },
  MAC:            { level: "high",   score: 0.95, reason: "MAC address" },
  PAN_INDIA:      { level: "high",   score: 0.95, reason: "Indian PAN structure (AAAAA1234A)" },
  NINO_UK:        { level: "high",   score: 0.94, reason: "UK National Insurance number with a valid prefix" },
  ETH_ADDRESS:    { level: "high",   score: 0.97, reason: "Ethereum address (0x + 40 hex)" },
  BTC_ADDRESS:    { level: "high",   score: 0.95, reason: "Bitcoin address format" },
  DOB:            { level: "high",   score: 0.92, reason: "Date next to a date-of-birth label" },
  ID:             { level: "high",   score: 0.90, reason: "Value next to a personal-identifier label" },
  CUSTOM:         { level: "high",   score: 0.99, reason: "Matched one of your always-mask terms" },
  // Credentials. A leaked key is exploitable the moment it is public, so these sit at the top of
  // the scale — and note we now rate the wallet PRIVATE key above the wallet address.
  API_KEY:        { level: "high",   score: 0.99, reason: "Provider-issued API key format" },
  PRIVATE_KEY:    { level: "high",   score: 0.99, reason: "Private key block" },
  SEED_PHRASE:    { level: "high",   score: 0.98, reason: "Wallet recovery phrase (BIP-39 word shape)" },
  JWT:            { level: "high",   score: 0.97, reason: "JSON Web Token structure" },
  CONNECTION_STRING: { level: "high", score: 0.97, reason: "Connection URI with an inline password" },
  SECRET:         { level: "high",   score: 0.90, reason: "Value assigned to a credential-named field" },
  VIN:            { level: "medium", score: 0.75, reason: "VIN: valid check digit, a known manufacturer code, or labelled as a VIN" },
  PHONE:          { level: "medium", score: 0.75, reason: "Phone-number shape" },
  STREET_ADDRESS: { level: "medium", score: 0.70, reason: "Street number followed by a named street and a street type" },
  PERSON:         { level: "medium", score: 0.70, reason: "Known first name followed by a capitalised surname (or an honorific)" },
};
const LEVEL_SCORE = { high: 0.95, medium: 0.7, low: 0.5 };
/** Confidence for any type, including user-defined custom regex types (explicit → high). */
export function confidenceFor(type) {
  return CONFIDENCE[type] || { level: "high", score: 0.96, reason: `Matched your custom "${type}" pattern` };
}
/** FNV-1a — a small, dependency-free, deterministic hash (client and server agree). */
function fnv1a(str) {
  let h = 0x811c9dc5;
  for (let i = 0; i < str.length; i++) { h ^= str.charCodeAt(i); h = Math.imul(h, 0x01000193) >>> 0; }
  return h.toString(36);
}
/**
 * Stable id for a finding — value-level, so approving/rejecting one applies everywhere it
 * appears. The value is HASHED, never embedded: apply-time responses echo ids back, and an id
 * that contained the raw value would leak the very data we just redacted.
 */
export function findingId(type, value) {
  return `${type}::${fnv1a(String(value).trim().toLowerCase())}`;
}

/** Precedence when spans overlap (higher wins). Keeps CARD/ID over PHONE. */
let SA_ID_LAST_LUHN = true;   // set by SA_ID.validate, read immediately after in _chosen
let IBAN_LAST_MOD97 = true;
/**
 * How strong the evidence is that a 17-character run is a VIN. Set by VIN.validate, read
 * immediately after, like IBAN_LAST_MOD97.
 *
 * Any 17 letters and digits used to be a VIN, which accepted nearly every random hex id there is,
 * and the leak audit filled with session tokens and hashes reported as vehicles. What actually
 * distinguishes a VIN (ISO 3779; 49 CFR 565):
 *
 *   checksum  position 9 is a valid check digit. Compulsory in North America and China, so a VIN
 *             from there proves itself; 1 in 11 random strings pass, which is why it is not the
 *             only door.
 *   shape     a known manufacturer code, or VW's ZZZ filler at 4-6. Europe and South Africa do
 *             NOT require the check digit (a VW SA "AAVZZZ6SZGU028694" fails it), so for those
 *             the manufacturer code is the evidence instead.
 *   vin_weak  anything else VIN-shaped. Below the reporting floor on its own; a nearby "VIN",
 *             "chassis" or "vehicle" lifts it over. This is what AWS Macie requires for every VIN.
 *   null      never a VIN: mixed case (a token, not a stamped plate), a leading 0 (no region uses
 *             it), or a last four that are not digits (the serial number always ends in digits).
 *
 * Lower case is allowed only as vin_weak: people type "my vin is 1hgbh…", ids are lower case too.
 * Hex-only is always vin_weak, because hex is what ids are made of.
 */
let VIN_LAST_TIER = "shape";
const VIN_TRANSLIT = { A: 1, B: 2, C: 3, D: 4, E: 5, F: 6, G: 7, H: 8, J: 1, K: 2, L: 3, M: 4, N: 5, P: 7, R: 9, S: 2, T: 3, U: 4, V: 5, W: 6, X: 7, Y: 8, Z: 9 };
const VIN_WEIGHTS = [8, 7, 6, 5, 4, 3, 2, 10, 0, 9, 8, 7, 6, 5, 4, 3, 2];
/** World manufacturer codes common in the markets we serve, by their first two characters. */
const VIN_WMI2 = new Set(["AA", "AB", "AC", "AD", "AF", "AH", "JA", "JF", "JH", "JM", "JN", "JS", "JT", "KL", "KM", "KN",
  "LS", "LV", "MA", "MR", "SA", "SB", "SC", "TM", "VF", "VS", "WA", "WB", "WD", "WF", "WM", "WP", "WV", "W0", "YV", "ZA", "ZF"]);
export function vinTier(raw) {
  const v = String(raw);
  if (/[a-z]/.test(v) && /[A-Z]/.test(v)) return null;
  if (v[0] === "0" || !/\d{4}$/.test(v) || !/[A-Z]/i.test(v)) return null;
  const u = v.toUpperCase();
  let sum = 0;
  for (let i = 0; i < 17; i++) sum += (/\d/.test(u[i]) ? +u[i] : VIN_TRANSLIT[u[i]]) * VIN_WEIGHTS[i];
  const check = sum % 11 === 10 ? "X" : String(sum % 11);
  // Hex before the check digit: 1 in 11 hex ids passes it by chance, and a real VIN made only of
  // 0-9 and A-F is vanishingly rare, so hex has to be labelled whatever its check digit says.
  if (v !== u || /^[0-9A-F]+$/.test(u)) return "vin_weak";
  if (u[8] === check) return "checksum";
  if (u.slice(3, 6) === "ZZZ" || VIN_WMI2.has(u.slice(0, 2))) return "shape";
  return "vin_weak";
}   // same pattern: the checksum grades confidence, it does not gate
const TYPE_PRECEDENCE = {
  // Credentials outrank everything. A connection string contains an email-shaped substring and a
  // PEM block contains base64 that trips other patterns; whichever wins the span decides what the
  // reviewer is told, and "you leaked a database password" beats "you leaked an email address".
  PRIVATE_KEY: 130, CONNECTION_STRING: 120, SEED_PHRASE: 118, API_KEY: 115, JWT: 112, SECRET: 108,
  EMAIL: 100,
  ETH_ADDRESS: 96, BTC_ADDRESS: 96, MAC: 97, IPV6: 95, VIN: 94,
  IBAN: 90,
  PAN_INDIA: 88, NINO_UK: 88, AADHAAR: 87,
  SA_ID: 85,
  CREDIT_CARD: 80,
  SSN: 70,
  DOB: 68, ID: 66,
  IPV4: 60,
  STREET_ADDRESS: 58, CUSTOM: 55,
  PERSON: 50,
  PHONE: 40,
};

/**
 * Precedence for one match, honouring where it came from.
 *
 * A rule the workspace wrote is a DECLARATION, not a guess: someone typed `EMP-123456` into the
 * pattern builder and named it. So it outranks every heuristic — without this, the generic
 * "labelled identifier" pickup claims `Employee EMP-445192` first and the reviewer sees `[ID_1]`
 * instead of the `[EMPLOYEE_ID_1]` they defined, which reads as their rule having been ignored.
 *
 * It stays BELOW the credential block on purpose. If a hand-written pattern happens to straddle an
 * API key, "you leaked an API key" is still the more useful thing to say than the custom label.
 */
const CUSTOM_PRECEDENCE = 105; // above every heuristic, below PRIVATE_KEY…SECRET (108+)
function precedenceOf(m) {
  const base = TYPE_PRECEDENCE[m.type] || 0;
  if (m.via === "token_literal") return 200;   // nothing may leave part of a forged token standing
  if (m.via === "custom") return Math.max(base, CUSTOM_PRECEDENCE);
  // Lowest of all: the sweep exists to catch what the detectors MISSED. Ranking it above them
  // made a swept name-fragment beat the real email match and split the address in half.
  // Among swept spans themselves the length tiebreak decides, so the longest variant wins.
  // Only a SWEPT span ranks bottom — it exists to fill gaps the detectors left, so it must never
  // outrank one. An existing match upgraded to "established" keeps its own standing: demoting it
  // handed `"tax_number": "0123456789"` back to the phone detector, which had merely recognised
  // the shape of it. `swept` is what tells the two apart.
  if (m.swept !== undefined) return 1;
  // "established" raises CONFIDENCE, not rank. Bumping rank as well put a shape-derived PHONE span
  // above the checksum-derived CREDIT_CARD span covering the same digits, and a spaced Amex number
  // came back as [PHONE_1].
  if (m.via === "established") return base;
  // A label DECLARED this. That beats any detector that merely recognised the shape of it.
  // A label lifts a value above a SHAPE guess about the same characters — that is what stopped
  // `"tax_number": "0123456789"` being reported as a phone. It must not lift it above a checksummed
  // type, though: set too high, it made "ID 9008130035084" a generic [ID_1] instead of an SA ID,
  // and a card lose to the word beside it.
  if (m.via === "label" || m.via === "field") return Math.max(base, 70);
  return base;
}

/**
 * Heuristic PERSON detection (zero-dep, no ML). Finds runs of Titlecase words and keeps them
 * only on a real name signal. Returns [{start,end,type,value}].
 *
 * `mode` is the workspace's "Name matching" setting, and it is honoured here:
 *
 *   "strict"   — keep a name ONLY where the first-name gazetteer anchors it ("John Smith").
 *                Nothing is inferred. This is the dashboard's "known first names only".
 *   "balanced" — the above, PLUS a name introduced by an honorific ("Mr Naledi Khumalo") whose
 *                given name we do not know. The honorific is the signal; the name is the guess.
 *                The default.
 *
 * Neither mode keeps a bare Title-Case phrase with no signal at all. "Port Louis" and "Standard
 * Bank" are shaped exactly like a name, and masking them is the false-positive class that
 * redaction-corpus.test.mjs exists to prevent. A signal is always required.
 */
/** "M. E. Delacroix", "J.R.R. Tolkien" — initials followed by a surname. */
const INITIALS_NAME = /(?<![\p{L}\p{N}])(?:\p{Lu}\.[ \t]?){1,3}\p{Lu}[\p{L}\p{M}'’\-]*[\p{Ll}\p{M}'’](?![\p{L}\p{N}])/gu;

/**
 * Does the last token of a run vouch for the whole run being a person?
 *
 * The given-name anchor cannot see half the world: "Xanthe", "Ottoline", "Saoirse" and "Aeryn" are
 * in no public corpus. Their surnames usually are, so the surname gets to anchor too.
 *
 * Three refusals make that safe. A surname that is also an ordinary English word may not anchor
 * anything on its own, or "Notting Hill", "Camp Baker" and "Cost Price" are all people — it still
 * masks behind a known given name, which is the other anchor's job. The run may not START on a
 * stopword, because "the Ridley report" is a document. And it may not start on a word that begins a
 * place, because "Port Louis" and "Los Angeles" end in perfectly good surnames.
 */
function surnameAnchors(lower) {
  // EXACTLY two words. This is the weakest evidence of the three anchors — one half of the name is
  // unknown and the other is doing all the work — so it is given the least room. Three-word runs
  // are where product and company phrases live: "Widget Pro Max", "Acme Holdings Ltd", "Q3 Report
  // Final". A genuine three-word name almost always has a known given name or a particle in it,
  // and both of those are anchored elsewhere.
  if (lower.length !== 2) return false;
  const [first, last] = lower;
  if (!last || NAME_STOPWORDS.has(first) || PLACE_PREFIXES.has(first)) return false;
  return isSurname(last) && !isWordSurname(last);
}

/**
 * Cues that introduce a name in a sentence, rather than a label that declares one.
 *
 * "Name:" was already handled, because a colon is a schema of sorts. What was not handled is every
 * way a person actually writes: a greeting, an introduction, a sign-off. Those are the shapes that
 * arrive in a chat box, and they were the whole reason a customer could type their own name and
 * watch nothing happen.
 *
 * The cue is the evidence here, not the name, so a name in no list on earth still masks — the only
 * path by which a name as rare as "Aeryn Quarmby" gets caught at all.
 *
 * The cue has to END on a boundary as well as start on one. Without that, "hi" matched inside
 * "hill" and "let grace hill know" masked "ll know": any cue that is a prefix of an ordinary word
 * will otherwise anchor a name in the middle of it.
 */
const NAME_CUE = new RegExp(
  "(?<![\\p{L}])(dear|hi|hello|hey|greetings"
  + "|my name is|i am|i'm|this is"
  + "|kind regards|best regards|warm regards|best wishes|yours sincerely|yours faithfully"
  + "|regards|many thanks|thank you|thanks|sincerely|cheers)"
  + "(?![\\p{L}\\p{N}])"
  + "[,:]?[ \\t]*\\r?\\n?[ \\t]*"
  + "([\\p{L}][\\p{L}\\p{M}'’.\\-]*(?:[ ]+[\\p{L}][\\p{L}\\p{M}'’.\\-]*){0,2})",
  "giu"
);

/**
 * Cues strong enough to introduce a name in any case at all.
 *
 * "my name is aeryn quarmby" is a name however it is typed, and someone typing their own name into
 * a chat box very often does not capitalise it. Every other cue is a phrase that ordinary prose
 * also uses — "this is more efficient than reading files one by one", which is a real MCP tool
 * description that this masked as a person — so the rest have to see a capital letter before they
 * will believe what follows is somebody's name.
 */
const STRONG_CUE = /^(?:my name is|i am|i'm)$/i;

/**
 * The name a cue introduced, or "" if what followed was not one.
 *
 * The run is cut at the first stopword, which is what separates "Dear Aoife Gallagher" from "Dear
 * Sir or Madam", "Hi there" and "Regards, the Support Team". What is left has to be two tokens, or
 * one token that is a name we actually know — otherwise "Dear Hiring Manager" cuts down to
 * "Hiring" and a job advert acquires a candidate.
 */
function nameAfterCue(run) {
  const toks = run.split(/\s+/).filter(Boolean);
  const kept = [];
  for (const t of toks) {
    if (NAME_STOPWORDS.has(t.toLowerCase().replace(/[.'’-]+$/, ""))) break;
    kept.push(t);
  }
  if (!kept.length) return "";
  if (kept.length === 1 && !isGivenName(kept[0].toLowerCase().replace(/[.'’-]+$/, ""))) return "";
  return kept.join(" ");
}

/**
 * One lowercase word, for the both-halves-known rule below.
 *
 * Every ADJACENT pair is tested, which is why this matches single words rather than pairs. A
 * two-word pattern consumes as it goes: in "let grace hill know" it takes "let grace", fails, and
 * resumes past "grace" — so "grace hill" is never looked at, and the name in the middle of the
 * sentence is the one that gets away.
 */
const LOWER_WORD = /(?<![\p{L}\p{N}])\p{Ll}[\p{L}\p{M}'’-]*(?![\p{L}\p{N}])/gu;

export function detectPersons(text, mode = "balanced") {
  const guessFromHonorific = mode !== "strict"; // strict will not infer a name it does not know
  const spans = [];
  // 1-3 Title-Case words. High precision: a bare Title-Case phrase is NOT enough (documents
  // are full of Title-Case headings/terms). We keep a span only with a real name signal:
  //   • a known first name followed by a Capitalised surname ("John Smith", "Thabo Mbeki"), or
  //   • an honorific, either in the span ("Mr Smith") or right before it ("Dr" "Jane Doe").
  for (const m of text.matchAll(INITIALS_NAME)) {
    spans.push({ start: m.index, end: m.index + m[0].length, type: "PERSON", value: m[0], via: "gazetteer" });
  }
  // The lowercase alternative inside the repeated group is a NAME PARTICLE: van, von, de, della.
  // Without it the run stops dead at the particle, so "Joost van Dijk" was read as "Joost" and
  // "Dijk" — two one-word runs, neither of which is a name — and every Dutch, German, Portuguese
  // and Spanish name in the document went unmasked. The list is closed and short on purpose: any
  // lowercase word allowed here is a word that can join two unrelated Title-Case phrases together.
  const re = /(?<![\p{L}\p{N}])\p{Lu}[\p{L}\p{M}'’.\-]*[\p{Ll}\p{M}'’](?:[ ]+(?:(?:van|von|der|den|del|della|de|di|da|dos|das|du|la|le|ter|ten|bin|ibn|al)[ ]+)?\p{Lu}[\p{L}\p{M}'’.\-]*[\p{Ll}\p{M}'’]){0,2}(?![\p{L}\p{N}])/gu;
  let m;
  while ((m = re.exec(text)) !== null) {
    // Trim a trailing file extension before anything else.
    //
    // The pattern allows a dot INSIDE a word so that "St.John" and initials survive. That also
    // lets "CV.pdf" pass as a Title-Case word — so once the sweep turns separators into spaces,
    // "Amara_Okonkwo_CV.pdf" reads as a three-word name and the whole filename is masked,
    // extension and all, while "Amara_Okonkwo_CV_2026.pdf" escapes only because a digit happens
    // to break the run. Same record, two different answers, and the shielded filename stops
    // looking like a file.
    //
    // A dot in a NAME is an abbreviation and is followed by a capital or by nothing ("St.John",
    // "Jr."). A dot in a FILENAME is followed by lowercase. That is the whole distinction.
    const value = m[0].replace(/(?:[ ]+[\p{L}\p{M}'’.\-]*\.[a-z]{2,5})+$/u, "");
    if (!value || /^[\p{L}\p{M}'’\-]*\.[a-z]{2,5}$/u.test(value)) continue;
    const start = m.index;
    const tokens = value.split(/\s+/);
    const lower = tokens.map((t) => t.toLowerCase().replace(/[.'’-]+$/, ""));
    if (lower.every((t) => NAME_STOPWORDS.has(t))) continue;

    let keep = false, s = start, v = value, viaHonorific = false, viaSurname = false;

    // Honorific as the first token: "Mr Smith", "Dr Jane Doe" → the run after the title.
    if (HONORIFICS.has(lower[0]) && tokens.length >= 2) {
      const rel = value.indexOf(tokens[1]);
      keep = true; viaHonorific = true; s = start + rel; v = value.slice(rel);
    } else {
      // Honorific immediately before the span: "Dr" then "Jane Doe".
      const pre = text.slice(Math.max(0, start - 14), start);
      const honBefore = /\b([A-Za-z]{2,12})\.?\s+$/.exec(pre);
      const knownIdx = lower.findIndex((t) => isGivenName(t));
      if (honBefore && HONORIFICS.has(honBefore[1].toLowerCase())) {
        keep = true; viaHonorific = true;
      } else if (knownIdx >= 0 && knownIdx < tokens.length - 1) {
        // Known first name with a following surname → keep from the first name onward.
        const rel = value.indexOf(tokens[knownIdx]);
        keep = true; if (rel > 0) { s = start + rel; v = value.slice(rel); }
      } else if (guessFromHonorific && tokens.length >= 2 && surnameAnchors(lower)) {
        // SURNAME AS THE ANCHOR. Half the world's given names are in no corpus — "Xanthe",
        // "Ottoline", "Aeryn" — but their surnames very often are, and a capitalised word in front
        // of a real surname is a person far more often than it is anything else.
        keep = true; viaSurname = true;
      }
      // A lone known first name ("John"), or a bare Title-Case phrase with nothing known in it
      // (e.g. the place name "Port Louis") → NOT kept: too noisy without an anchor.
    }

    // STRICT: the honorific alone is a guess, and strict does not guess. "Dr Sarah Johnson"
    // survives because Sarah is in the gazetteer; "Mr Naledi Khumalo" does not, because the only
    // thing telling us Naledi is a person is the "Mr".
    if (keep && viaHonorific && !guessFromHonorific) {
      const kept = v.split(/\s+/).map((t) => t.toLowerCase().replace(/[.'’-]+$/, ""));
      if (!kept.some((t) => isGivenName(t))) keep = false;
    }

    if (keep) {
      // Trim a trailing stopword the pattern swallowed ("Jane Doe Please" → "Jane Doe").
      let vt = v.split(/\s+/);
      while (vt.length > 1 && NAME_STOPWORDS.has(vt[vt.length - 1].toLowerCase().replace(/[.'’-]+$/, "")) && !isGivenName(vt[vt.length - 1].toLowerCase())) {
        v = v.slice(0, v.lastIndexOf(vt[vt.length - 1])).replace(/\s+$/, ""); vt = v.split(/\s+/);
      }
      // How it was proven: an honorific-only guess is weaker evidence than a known first name, and
      // the scorer must be able to tell them apart. If the kept value contains a gazetteer name,
      // that is the stronger signal even when an honorific was also present.
      if (v) {
        const gaz = v.split(/\s+/).some((t) => isGivenName(t.toLowerCase().replace(/[.'’-]+$/, "")));
        spans.push({
          start: s, end: s + v.length, type: "PERSON", value: v,
          via: gaz ? "gazetteer" : (viaSurname ? "surname" : "honorific"),
        });
      }
    }
  }
  // ---- ALL-CAPS names. A CV header is almost always "PRIYA RAMESH", never "Priya Ramesh", so the
  // Title-Case pass above misses the single most important name on the page — the candidate's own.
  // Gated hard on the gazetteer: the FIRST word must be a given name we know. That keeps section
  // headings ("EXPERIENCE", "EDUCATION") and employers ("NORTHWIND HEALTH") out, since none of
  // their leading words are first names. It is exactly as precise as the Title-Case path, and no
  // more: a company named after a person reads as a person in both.
  const caps = /\b[A-Z][A-Z'’.\-]*[A-Z](?:[ \t]+[A-Z][A-Z'’.\-]*[A-Z]){1,2}\b/g;
  let cm;
  while ((cm = caps.exec(text)) !== null) {
    const value = cm[0];
    const toks = value.split(/\s+/).map((t) => t.toLowerCase().replace(/[.'’-]+$/, ""));
    if (!isGivenName(toks[0]) && !surnameAnchors(toks)) continue;  // anchored, not merely shouty
    if (toks.some((t) => NAME_STOPWORDS.has(t))) continue;
    if (spans.some((sp) => cm.index < sp.end && cm.index + value.length > sp.start)) continue; // already found
    spans.push({ start: cm.index, end: cm.index + value.length, type: "PERSON", value, via: "gazetteer" });
  }

  // ---- Names a sentence introduces. See NAME_CUE. The greeting itself is left alone: only the
  // captured run is masked, so "Dear [PERSON_1]" still reads as a letter.
  let cue;
  NAME_CUE.lastIndex = 0;
  while ((cue = NAME_CUE.exec(text)) !== null) {
    const run = cue[2];
    if (!STRONG_CUE.test(cue[1]) && !/^\p{Lu}/u.test(run)) continue;
    const name = nameAfterCue(run);
    if (!name) continue;
    const at = cue.index + cue[0].lastIndexOf(run);
    if (spans.some((sp) => at < sp.end && at + name.length > sp.start)) continue;   // already found
    spans.push({ start: at, end: at + name.length, type: "PERSON", value: name, via: "cue" });
  }

  // ---- Lowercase names. Capitalisation had been a hard requirement, so "jennifer botha" typed
  // into a chat box sailed through while "Jennifer Botha" did not. A lowercase pair is kept only
  // when BOTH halves are known — a given name AND a surname — because one half is the shape of
  // ordinary prose ("mark the box", "review the code") and would flood every document.
  //
  // The cost of this is real and was accepted deliberately: "will smith the deal" masks, because
  // "will" is a given name and "smith" is a surname and nothing in the text says otherwise. The
  // scorer knows — an uncapitalised person loses 0.2 confidence — so it reports as a weak finding
  // rather than a certainty.
  const words = [];
  let lw;
  LOWER_WORD.lastIndex = 0;
  while ((lw = LOWER_WORD.exec(text)) !== null) words.push({ w: lw[0], at: lw.index });
  for (let i = 0; i + 1 < words.length; i++) {
    const a = words[i], b = words[i + 1];
    if (b.at !== a.at + a.w.length + 1 || text[a.at + a.w.length] !== " ") continue;  // one space, nothing else
    if (!isGivenName(a.w) || !isSurname(b.w)) continue;
    const at = a.at, end = b.at + b.w.length;
    if (spans.some((sp) => at < sp.end && end > sp.start)) continue;
    spans.push({ start: at, end, type: "PERSON", value: text.slice(at, end), via: "gazetteer" });
  }

  return spans;
}

// Label-driven detection — always on. Catches PII a value-shape regex can't recognise
// alone: a lowercase name ("name aeryn quarmby") or any labelled identifier ("medical
// aid number 1273829", "policy 44821", "account no A-9912"). This is the auto-pickup:
// new/unknown identifier kinds get masked the instant they appear by their label.
// A labelled name is either "<label>: value" (delimiter — value may be on the next line) or
// "<strong label>  value" on the SAME line. The bare word "name" needs a delimiter, so a
// form field header like "Approver Name" on its own line doesn't swallow the next line.
// Two shapes. m[1] is the DELIMITER form ("Name: jane doe") — a person typed an explicit field, so
// we trust a lowercase value. m[2] is the DELIMITER-FREE form ("Patient John Smith") — no punctuation
// separates label from value, so ordinary prose ("the name behind it") lands here too, and the value
// must look like a name (Title-Case, or gazetteer-anchored) before we believe it. The weak labels
// (contact/client/customer/member/holder/owner) were dropped: they tag companies and prose far more
// often than people ("Client: Acme Holdings", "the member states disagreed").
const LABEL_NAME = /\b(?:full name|first name|last name|sur\s?name|name|patient|beneficiary|cardholder|account holder)\s*[:=]\s*(\p{L}[\p{L}\p{M}'’\-]+(?:[ ]+\p{L}[\p{L}\p{M}'’\-]+){0,2})|\b(?:full name|first name|last name|sur\s?name|name|patient|beneficiary|cardholder|account holder)[ \t]+(\p{L}[\p{L}\p{M}'’\-]+(?:[ ]+\p{L}[\p{L}\p{M}'’\-]+){0,2})/giu;
// Personal identifier labels only. Generic transactional/document labels (reference, order,
// invoice, file, record, case, folio) are deliberately excluded — in business documents they
// tag non-personal numbers and caused over-masking.
const LABEL_ID = /\b(?:medical aid|health plan|scheme|policy|membership|account|acc|passport|licen[cs]e|employee|staff|customer|tax|vat|national id|id|patient)\s*(?:numbers?|no\.?|nr|#|id)?\s*[:=#]?\s+([A-Za-z0-9][A-Za-z0-9\-/]{3,})/gi;
// Date of birth: a DOB label + a date value (numeric or "1 January 1990"). We mask the DATE
// only when it's a birth date — plain dates elsewhere stay (they're not personal on their own).
const LABEL_DOB = /\b(?:date of birth|d\.?\s?o\.?\s?b\.?|birth\s?date|date born|born(?:\s+on)?)\s*[:=]?[ \t]*[.…_]{0,60}[ \t]*((?:\d{1,4}[-/.]\d{1,2}[-/.]\d{1,4})|(?:\d{1,2}(?:st|nd|rd|th)?\s+[A-Za-z]{3,9},?\s+\d{4})|(?:[A-Za-z]{3,9}\s+\d{1,2}(?:st|nd|rd|th)?,?\s+\d{4}))/gi;
// The same labels, as STRUCTURED-DATA field names. A name has no shape of its own — "Jennifer" is
// just a word — so the label is the entire signal, and in JSON it arrives written differently:
// `"first_name": "Jennifer"`. The underscore stops \b(?:first name) from matching and the quotes sit
// between the delimiter and the value, so the prose regexes above miss it completely. That is how a
// Greenhouse candidate whose name is split across first_name/last_name passed through untouched
// while the identical record with a joined `name` was redacted.
//
// Deliberately delimiter-ONLY (no bare "label value" form). These patterns are looser about the
// label than the prose ones, so requiring an explicit ':' or '=' keeps them out of ordinary
// sentences, where LABEL_NAME already does the work.
//
// The leading lookbehind is what stops `"company_name"` and `"file-name"` from being read as name
// fields. Inside `company_name` there is no word boundary before `name` (an underscore is a word
// character) so \b already excludes it, but a hyphen is not, and `company-name: Acme Logistics`
// would otherwise mask the company.
const NAME_WORDS = "full|first|given|last|sur|family|middle|preferred|maiden";
/**
 * Whose name a `<something>_name` field holds.
 *
 * The lookbehind above correctly refuses `company_name` and `file-name`. It also refused
 * `candidate_name`, `employee_name` and `patient_name` — which is what an ATS, an HR system and
 * a clinic actually call the column, so the one field guaranteed to hold a person was the one
 * being skipped. It mattered most in the case the guide points people at: an unusual given name
 * that free-text detection misses is supposed to be caught by the field declaring it.
 *
 * A curated list, not `\\w+_name`. "company", "file", "product", "brand", "table" and "project" all
 * end in _name and none of them is a person; masking those would destroy the record instead of
 * protecting it. Left out on purpose: customer, client, account, vendor, supplier, partner. In a
 * CRM those hold an organisation at least as often as a human ("customer_name": "Acme Ltd"), and
 * over-masking a company name breaks the work without protecting anybody.
 */
const PERSON_FIELD_WORDS = "candidate|applicant|employee|staff|patient|student|person|individual|contact"
  + "|recruiter|guest|tenant|driver|passenger|subscriber|author|beneficiary|dependent|nominee";
/**
 * An optional quote, optionally escaped.
 *
 * MCP results routinely carry JSON as a STRING inside JSON, so the inner document arrives as
 * `\"date_of_birth\":\"1951-05-17\"` — the quote is preceded by a backslash. Matching only a
 * bare quote meant every structured field inside a nested payload was invisible, and a date of
 * birth two levels down came through in the clear while the identical record one level up was
 * masked.
 */
const Q = '\\\\*"?';
const FIELD_VALUE = "(\\p{L}[\\p{L}\\p{M}'’\\-]+(?:[ \\t]+\\p{L}[\\p{L}\\p{M}'’\\-]+){0,2})";
const FIELD_NAME = new RegExp(

  `(?<![A-Za-z][_\\-])\\b(?:(?:${NAME_WORDS})[_\\-\\s]?names?|names?|candidate|applicant|(?:${PERSON_FIELD_WORDS})[_\\-\\s]names?)` +
  `(?:${Q}\\s*[:=]\\s*${Q}|>\\s*)${FIELD_VALUE}`, "giu");
const ID_WORDS = "passport|national[_\\-\\s]?id|identity[_\\-\\s]?(?:number|no)|id[_\\-\\s]?(?:number|no)\\b|tax|vat|ssn|social[_\\-\\s]?security|nino|drivers?[_\\-\\s]?licen[cs]e|licence|license|medical[_\\-\\s]?aid";
const FIELD_ID = new RegExp(
  `(?<![A-Za-z0-9][_\\-])\\b(?:${ID_WORDS})[_\\-\\s]?(?:number|no|nr|ref|reference)?` +
  `${Q}\\s*[:=]\\s*${Q}([A-Za-z0-9][A-Za-z0-9\\-/]{4,})`, "gi");
const FIELD_DOB = new RegExp(
  `(?<![A-Za-z][_\\-])\\b(?:date[_\\-\\s]?of[_\\-\\s]?birth|birth[_\\-\\s]?date|birthday|dob)` +
  `(?:${Q}\\s*[:=]\\s*${Q}|>\\s*)((?:\\d{1,4}[-/.]\\d{1,2}[-/.]\\d{1,4})|(?:\\d{1,2}(?:st|nd|rd|th)?\\s+[A-Za-z]{3,9},?\\s+\\d{4})|(?:[A-Za-z]{3,9}\\s+\\d{1,2}(?:st|nd|rd|th)?,?\\s+\\d{4}))`, "gi");

// Which OBJECT KEYS carry the same signal, for callers that walk structured data leaf by leaf and
// therefore never have the key and the value in one string (the MCP wrapper). Anchored whole-key on
// purpose: `company_name` and `file_name` must not match, or an agent loses the company it is
// recruiting for. `id` is deliberately absent — masking an ATS record id is not a safe default, it
// breaks the agent's ability to fetch the record it was just told about.
const KEY_NAME = new RegExp(`^(?:(?:${NAME_WORDS})[_\\- ]?)?names?$|^(?:candidate|applicant|patient|beneficiary|cardholder|account[_\\- ]?holder)(?:[_\\- ]?name)?$`, "i");
const KEY_DOB = /^(?:date[_\- ]?of[_\- ]?birth|birth[_\- ]?date|birthday|dob)$/i;
/**
 * Keys that name a personal IDENTIFIER. A passport number sitting under `passport` was being missed
 * while the same number was caught in prose two fields later — the field name says what it is at
 * least as plainly as a sentence does. Deliberately excludes bare `id` and anything that reads like
 * a record pointer.
 */
const KEY_ID = /^(?:passport(?:[_\- ]?(?:no|number))?|national[_\- ]?id(?:[_\- ]?number)?|id[_\- ]?number|identity[_\- ]?number|tax(?:[_\- ]?(?:no|number|ref|reference))?|ssn|social[_\- ]?security(?:[_\- ]?number)?|nino|ni[_\- ]?number|driver'?s?[_\- ]?licen[cs]e(?:[_\- ]?number)?|medical[_\- ]?aid(?:[_\- ]?number)?)$/i;

/**
 * The prose label to stand in front of a value so the engine can see what the key was saying.
 * Canonical rather than derived from the key: the probe only exists for detection and is never
 * shown, so "full name" — which every name path already understands — beats reconstructing
 * "preferred name" and hoping the vocabulary covers it.
 */
export function fieldLabel(key) {
  if (typeof key !== "string") return null;
  if (KEY_NAME.test(key)) return "full name";
  if (KEY_DOB.test(key)) return "date of birth";
  if (KEY_ID.test(key)) return "national id";
  return null;
}

const norm = (t) => t.toLowerCase().replace(/[.'’-]+$/, "");
const MONTHS = new Set(["jan","feb","mar","apr","may","jun","jul","aug","sep","oct","nov","dec",
  "january","february","march","april","june","july","august","september","october","november","december"]);

/**
 * Does the value captured after a name-label actually look like a name?
 *
 * This is the guard that was missing. The old path took any 1–3 words after "name" and called them
 * a person, which is how "the name behind it" became a PERSON in the Leak Audit. A real name is
 * either Title-Case, or anchored by a first name we know. Prose ("behind it", "outcome improved")
 * is neither. `explicit` relaxes the casing rule for the "Name: value" form, where the delimiter is
 * a person's deliberate declaration that what follows is a name — so "cardholder: jane doe" survives.
 * Returns the trimmed value, or null to reject.
 */
function validName(cap, explicit) {
  const toks = cap.split(/\s+/).filter(Boolean);
  let keep = toks.length;
  while (keep > 1 && NAME_STOPWORDS.has(norm(toks[keep - 1])) && !isGivenName(norm(toks[keep - 1]))) keep--;
  const kept = toks.slice(0, keep);
  if (!kept.length) return null;
  if (NAME_STOPWORDS.has(norm(kept[0]))) return null;         // "of the file", "not provided"
  const titleCase = kept.every((t) => /^[A-Z]/.test(t));
  const known = kept.some((t) => isGivenName(norm(t)));
  if (!explicit && !titleCase && !known) return null;         // delimiter-free lowercase prose
  // Return the EXACT prefix of cap (original spacing) so downstream offsets stay right.
  let idx = 0, end = 0;
  for (let i = 0; i < keep; i++) { idx = cap.indexOf(kept[i], idx); end = idx + kept[i].length; idx = end; }
  return cap.slice(0, end);
}

/** A birth-date value is only a date if it is a plausible calendar date — not "3 Widget 2020". */
function validDate(val) {
  if (!/\b(1[89]\d\d|20\d\d)\b/.test(val)) return false;                    // a plausible year
  const nums = (val.replace(/(st|nd|rd|th)\b/gi, "").match(/\d{1,4}/g) || []).map(Number);
  if (nums.some((n) => n > 31 && n < 1000)) return false;                   // "99/99/9999", not a day/month/year
  const monthName = val.match(/[A-Za-z]{3,9}/);
  if (monthName && !MONTHS.has(monthName[0].toLowerCase())) return false;   // "born on 3 Widget 2020"
  return true;
}

/**
 * Drop shape-only matches that sit inside a long base64 run.
 *
 * MCP returns images, audio and file contents as base64, and the alphabet includes digits and
 * letters, so a blob reliably contains runs that look like a VIN, a phone or an IP. Replacing one
 * with a token does not protect anybody — there is no person in there to protect — it just corrupts
 * the attachment, silently, on roughly one blob in fifty.
 *
 * Only SHAPE evidence is dropped. A checksummed card, a structural email or a credential prefix
 * inside a blob is a real finding and stays: those cannot be hit by accident, which is the whole
 * distinction the `via` field exists to draw.
 */
const B64_RUN = /[A-Za-z0-9+/]{64,}={0,2}/g;
const SHAPE_ONLY = new Set(["shape", "sa_id_weak", "honorific"]);
function dropInsideBase64(text, matches) {
  if (!matches.length || text.length < 64) return matches;
  B64_RUN.lastIndex = 0;
  const runs = [];
  for (const m of text.matchAll(B64_RUN)) runs.push([m.index, m.index + m[0].length]);
  if (!runs.length) return matches;
  return matches.filter((m) => {
    if (!SHAPE_ONLY.has(m.via || "shape")) return true;
    return !runs.some(([a, b]) => m.start >= a && m.end <= b);
  });
}

/**
 * Do not start a match inside a JSON escape sequence.
 *
 * We redact flat text. When that text is a JSON document — which it is for most MCP results, tool
 * arguments and API payloads — a `\n` in the source is two characters here, a backslash and an `n`.
 * A value written straight after one has that `n` sitting against it:
 *
 *   "notes": "line one\nbob@acme.com"
 *
 * so the email detector legitimately matches `nbob@acme.com`, masks it, and leaves the backslash
 * orphaned against a token. The redacted document is then not valid JSON at all and the client that
 * asked for it cannot parse the reply — a far worse outcome than the one extra character.
 *
 * Nudging the start past the escape letter fixes both halves: the value is still masked, and `\n`
 * survives intact. Only the five letter escapes need this; `\"`, `\\`, `\/` and `\uXXXX` cannot
 * begin a value.
 */
function avoidJsonEscapes(text, matches) {
  if (!matches.length || !text.includes("\\")) return matches;
  for (const m of matches) {
    if (m.start <= 0 || text[m.start - 1] !== "\\") continue;
    if (!"nrtbf".includes(text[m.start])) continue;
    // An even run of backslashes before it means the backslash is itself escaped, so this is not
    // an escape sequence and the character is genuinely part of the text.
    let back = 0;
    for (let i = m.start - 1; i >= 0 && text[i] === "\\"; i--) back++;
    if (back % 2 === 0) continue;
    m.start += 1;
    m.value = String(m.value).slice(1);
  }
  return matches.filter((m) => m.value && m.end > m.start);
}

// ---------------------- Known-value sweep (embedded PII) ----------------------
//
// Every detector above reads a string and asks "is this a name / an email / a phone?".
// `https://linkedin.com/in/marcus-delacroix` is none of those — it is a URL — and yet it
// re-identifies in one click the person whose name, email, phone and date of birth the same record
// just tokenised. So does `Marcus_Delacroix_CV_2026.pdf`, and so does
// `…/files/marcus.delacroix%40example.com/cv.pdf`, which survived only because `@` was
// percent-encoded and the email pattern therefore did not match.
//
// This needs no new detector. Once a value has been identified as personal ANYWHERE, the record has
// told us what to look for, and the rest of it can be swept for that same value under other
// delimiters and encodings — a name is the same name whether joined by a space, a hyphen, an
// underscore or a dot.
//
// The danger is over-masking, so the sweep is deliberately narrow about what it will look for:
//   · the FULL name / address, tokens joined by any short run of punctuation — distinctive enough
//     to be safe anywhere;
//   · initial + surname ("mdelacroix"), which is how handles are built;
//   · the surname ALONE — but only inside something that looks like a URL, path or filename, and
//     only when it is long enough not to collide with an ordinary word. A candidate called Cook
//     must not have "cook" swept out of "cookbook.pdf".
// A lone FIRST name is never swept: it is not a distinctive identity, and sweeping it would
// tokenise every "marcus" in a payload.

/**
 * Is this safe to chase through the rest of the payload as a person's name?
 *
 * Propagating a name case-insensitively is powerful and blunt. A field-shaped reading of
 * "Independent Contractor" on a real contract became an established identity and its propagation
 * masked the document's own ALL-CAPS heading — which destroys the thing being protected.
 *
 * The anchor is a given name we actually know, or a script the gazetteer does not cover (where
 * capitalisation carries no signal and the field name is doing all the work anyway).
 *
 * KNOWN LIMIT: a Latin-script given name absent from the gazetteer — "Art" in "Art Vandelay" —
 * still propagates only in its full form and its exact case. The lone given name in a later
 * sentence is not swept. Widening that is a gazetteer problem, not a rule problem, and guessing
 * harder here costs more than it returns.
 */
function hasKnownGivenName(value) {
  // The script check comes FIRST. `valueTokens` matches ASCII runs only, so a Cyrillic or CJK name
  // produces no tokens at all and fell out of the empty-list guard before the escape hatch was
  // ever reached — which silently denied propagation to exactly the populations it was written for.
  if (/[^\x00-\x7f]/.test(String(value))) return true;   // any non-ASCII letter: José, Müller, Дмитрий, 陳大文
  const toks = valueTokens(value);
  if (!toks.length) return false;
  // A vocabulary blocklist was tried here instead and is not enough: a real contract contains
  // Title-Case phrases no reasonable list anticipates, and each one that slips through gets
  // propagated case-insensitively and masks a heading. The gazetteer is the only guard that held.
  return toks.some((t) => FIRST_NAMES.has(t));
}
/** How a rule for one whole line of a marked block begins. The panel builds the same prefix. */
const WHOLE_LINE_PREFIX = "(?<=(?:^|\\n)[ \\t\\u00a0]*)";
const CERTAIN_VIA = new Set(["checksum", "structural", "secret", "term", "custom", "token_literal", "established", "field"]);
/** Lowercased alphanumeric runs — the parts of a value that survive re-punctuation. */
const valueTokens = (v) => String(v).toLowerCase().match(/[a-z0-9]+(?:['’][a-z0-9]+)*/g) || [];
/**
 * Any short run of separators: " ", "-", "_", ".", "/" — or a percent-escape.
 * The escape has to be spelled out: %40 contains the digits 4 and 0, so a bare [^A-Za-z0-9] class
 * stops dead at them, and `marcus.delacroix%40example.com` went unmatched for precisely that reason.
 */
const SEP = "(?:%[0-9A-Fa-f]{2}|[^A-Za-z0-9]){0,3}";
const escRe = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
/** Words common enough that sweeping them would do more harm than the leak. */
const SWEEP_STOPWORDS = new Set(["cook", "baker", "smith", "brown", "green", "white", "black", "young",
  "king", "price", "rose", "hunter", "walker", "carter", "fisher", "gardener", "mason", "miller",
  "turner", "taylor", "wood", "field", "hill", "moore", "shaw", "stone", "wolf", "fox", "bell"]);
/** URLs, paths and filenames — the only places a lone surname is safe to sweep. */
const URLISH = /(?:[a-z][a-z0-9+.-]*:\/\/|www\.)[^\s"'<>]+|\/[A-Za-z0-9._~%\-/]{3,}|[A-Za-z0-9._~%-]+\.(?:pdf|docx?|xlsx?|pptx?|txt|csv|rtf|zip|png|jpe?g|gif|html?)\b/gi;

/**
 * Variant patterns for one already-identified value.
 * @returns {{re: RegExp, urlOnly: boolean}[]}
 */
function sweepPatterns(value, type) {
  const toks = valueTokens(value);
  // The case-SENSITIVE pattern has to be built from the value's ORIGINAL casing. Built from the
  // lowercased tokens it could only ever match all-lowercase text, which meant every sweep outside
  // a URL silently matched nothing: a record stating "Full name: Oliver Testcase" and then
  // carrying "Oliver_Testcase" elsewhere kept the second one, in full.
  const cased = String(value).match(/[A-Za-z0-9]+/g) || [];
  if (toks.length === 0) return [];
  const out = [];
  // Two passes over the same body. Case-SENSITIVE is allowed anywhere; case-INSENSITIVE only
  // inside a URL, path or filename, where slugs are lowercased by convention.
  //
  // Matching case-insensitively everywhere is what let a stray "Independent Contractor" reading
  // from the person detector spread to the ALL-CAPS heading of a contract and mask it — masking a
  // document's own headings destroys the thing being protected. It also breaks exact restoration,
  // because the token then stands for text of a different case than it replaced.
  const bounded = (body, urlOnly) =>
    ({ re: new RegExp(`(?<![A-Za-z0-9])${body}(?![A-Za-z0-9])`, urlOnly ? "gi" : "g"), urlOnly });

  if (toks.length >= 2) {
    // The full value, however it has been re-punctuated. Trailing digits come too, so a handle
    // like "mdelacroix87" is masked whole rather than leaving "87" behind.
    for (const ci of [false, true]) out.push(bounded((ci ? toks : cased).map(escRe).join(SEP) + "[0-9]*", ci));
    // The first two tokens — for an email this is the local part ("marcus.delacroix"), which
    // appears in paths without the domain.
    if (toks.length > 2) for (const ci of [false, true]) out.push(bounded((ci ? toks : cased).slice(0, 2).map(escRe).join(SEP) + "[0-9]*", ci));
    // Initial + surname, which is how usernames and handles are built.
    const surname = toks[1];
    if (surname.length >= 5) {
      for (const ci of [false, true]) {
        const t = ci ? toks : cased;
        out.push(bounded(escRe(t[0][0]) + SEP + escRe(t[1]) + "[0-9]*", ci));
      }
    }
  }
  // A single distinctive token, confined to URL-ish text. PERSON and EMAIL only: sweeping a lone
  // phone fragment or address word would be noise.
  if ((type === "PERSON" || type === "EMAIL") && toks.length >= 2) {
    const surname = toks[1];
    if (surname.length >= 6 && !SWEEP_STOPWORDS.has(surname)) {
      // Flagged, because this pattern matches a FRAGMENT of the value rather than the value. An
      // established address lets it match outside a URL too (see the `sure` bypass in _known),
      // and there a lone surname is a name, not an address. See `fragment` at the record site.
      out.push({ ...bounded(escRe(surname) + "[0-9]*", true), fragment: true });
    }
  }
  return out;
}

/** Header text -> the type of the column beneath it. Deliberately narrow. */
const COLUMN_TYPES = [
  [/^(?:(?:full|first|last|sur|given|middle|preferred|maiden)[_\- ]?name|name|(?:candidate|applicant|patient|employee|student|staff|recruiter|beneficiary|dependent|nominee)(?:[_\- ]?name)?|(?:customer|contact|client|person|individual|guest|tenant|driver|passenger|subscriber|author)[_\- ]?name)$/i, "PERSON"],
  [/^(?:date[_\- ]?of[_\- ]?birth|birth[_\- ]?date|birthday|dob)$/i, "DOB"],
  [/^(?:e[_\- ]?mail|email[_\- ]?address|email)$/i, "EMAIL"],
  [/^(?:phone|telephone|mobile|cell|contact[_\- ]?number|msisdn)$/i, "PHONE"],
  [/^(?:address|street[_\- ]?address|residential[_\- ]?address|home[_\- ]?address)$/i, "STREET_ADDRESS"],
];
const columnType = (h) => (COLUMN_TYPES.find(([re]) => re.test(String(h).trim().replace(/^\**|\**$/g, "")))
  || [])[1] || null;

/**
 * Split one table row into cells.
 *
 * For CSV this has to respect double quotes, because the single most common thing a quoted cell
 * contains is a comma, and the single most common such cell is an address. Splitting naively
 * turned `address,"221B Baker Street, London NW1 6XE"` into three cells, so only the first
 * fragment was masked and the postcode was left in the file.
 *
 * Cells keep their surrounding quotes, so `cells.join(delim)` still reconstructs the line exactly
 * and every character offset computed from cell lengths stays true.
 */
function splitRow(line, delim) {
  if (delim !== ",") return line.split(delim);
  const out = [];
  let cur = "";
  let inQuotes = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (ch === '"') { inQuotes = !inQuotes; cur += ch; continue; }
    if (ch === "," && !inQuotes) { out.push(cur); cur = ""; continue; }
    cur += ch;
  }
  out.push(cur);
  return out;
}

/** A cell's value without its CSV quoting, and how far in from the cell's start it begins. */
function cellValue(cell) {
  const lead = cell.length - cell.trimStart().length;
  const trimmed = cell.trim();
  if (trimmed.length > 1 && trimmed.startsWith('"') && trimmed.endsWith('"')) {
    return { lead: lead + 1, val: trimmed.slice(1, -1) };
  }
  return { lead, val: trimmed };
}

/**
 * Values named by a COLUMN HEADER or by the cell beside them, rather than by a label on the same
 * line. A CSV, TSV or markdown export of candidates says "date_of_birth" once, in row one, and then
 * lists two hundred dates — none of which any value-shape detector can recognise, because a date is
 * only a date of birth because the header says so.
 */
export function detectTabular(text) {
  if (!text || text.length < 8) return [];
  const spans = [];
  const lines = text.split("\n");
  let offset = 0;
  const lineStart = lines.map((l) => { const o = offset; offset += l.length + 1; return o; });

  for (const delim of ["\t", "|", ","]) {
    // The header is the first line that has at least one cell naming a personal field.
    for (let h = 0; h < Math.min(lines.length, 5); h++) {
      if (!lines[h].includes(delim)) continue;
      // A header row names fields; it does not carry data. Without this check the row
      // "| Date of birth | 1951-06-21 |" was read as a header, and every row beneath it had its
      // FIRST column masked — so the word "note" came back as [DOB_2].
      if (/\d{4}|@/.test(lines[h])) continue;
      const head = splitRow(lines[h], delim);
      // A quoted cell is data, not a field name: writers quote values because values are what
      // contain commas and spaces. Without this, `name,"Aeryn Quarmby"` in a two-column key/value
      // export reads as a header naming a NAME column, and every key beneath it gets masked as a
      // person. The row above already rejects headers carrying an address or a four-digit number
      // for the same reason; this is the same trade, on a stronger signal.
      if (head.some((c) => /^\s*".*"\s*$/.test(c))) continue;
      const cols = head.map(columnType);
      if (!cols.some(Boolean)) continue;
      for (let r = h + 1; r < lines.length; r++) {
        const row = splitRow(lines[r], delim);
        if (row.length !== head.length) continue;      // not part of this table
        let col = lineStart[r];
        for (let ci = 0; ci < row.length; ci++) {
          const cell = row[ci];
          const type = cols[ci];
          if (type) {
            const { lead, val } = cellValue(cell);
            // `!columnType(val)` is the same guard the label-beside-value rule below already has,
            // and it is what stops a key/value export eating itself: `name,"Aeryn Quarmby"` looks
            // enough like a header to be taken for one, and then every key under it — "email",
            // "phone", "card" — was masked as a person. A cell that is itself the name of a field
            // is a field name, not somebody's value.
            if (val && val.length > 1 && !/^-+$/.test(val) && !columnType(val)) {
              spans.push({ start: col + lead, end: col + lead + val.length, type, value: val, via: "field" });
            }
          }
          col += cell.length + delim.length;
        }
      }
      break;   // one header per delimiter is enough
    }

    // The other table shape: the label is the cell BESIDE the value, not the column above it.
    // "| Date of birth | 1951-06-21 |" is how a markdown table, an HTML detail table and half the
    // emails in the world present a record, and no column header ever names the field.
    for (let r = 0; r < lines.length; r++) {
      if (!lines[r].includes(delim)) continue;
      const cells = splitRow(lines[r], delim);
      let col = lineStart[r];
      const starts = cells.map((c) => { const o = col; col += c.length + delim.length; return o; });
      for (let ci = 0; ci < cells.length - 1; ci++) {
        const type = columnType(cells[ci]);
        if (!type) continue;
        const cell = cells[ci + 1];
        const { lead, val } = cellValue(cell);
        // A bare lowercase identifier beside a label is the NEXT column's name, not a value —
        // otherwise "id,date_of_birth,note" masks the word "note".
        if (val && val.length > 1 && !/^-+$/.test(val) && !columnType(val) && !/^[a-z][a-z0-9_]*$/.test(val)) {
          spans.push({ start: starts[ci + 1] + lead, end: starts[ci + 1] + lead + val.length, type, value: val, via: "field" });
        }
      }
    }
  }

  // HTML tables are the same idea with tags instead of pipes.
  const cells = [...text.matchAll(/<t[dh][^>]*>([\s\S]*?)<\/t[dh]>/gi)];
  for (let i = 0; i < cells.length - 1; i++) {
    const type = columnType(cells[i][1].replace(/<[^>]+>/g, ""));
    if (!type) continue;
    const raw = cells[i + 1][1];
    const inner = raw.replace(/<[^>]+>/g, "");
    if (inner !== raw) continue;                         // nested markup; leave it alone
    const at = cells[i + 1].index + cells[i + 1][0].indexOf(raw);
    const lead = raw.length - raw.trimStart().length;
    const val = raw.trim();
    if (val && val.length > 1 && !columnType(val)) {
      spans.push({ start: at + lead, end: at + lead + val.length, type, value: val, via: "field" });
    }
  }
  return spans;
}

/** "(née Boateng)", "born Nkosi" — the word says the next capitalised token is a surname. */
const MAIDEN = /\b(?:n[ée]e|born|formerly|previously|maiden name)\s+(\p{Lu}[\p{L}\p{M}'’\-]{1,30})/gu;

export function detectLabeled(text) {
  const spans = [];
  let m;
  LABEL_NAME.lastIndex = 0;
  while ((m = LABEL_NAME.exec(text)) !== null) {
    const cap = m[1] || m[2] || "";
    const val = validName(cap, !!m[1]); if (!val) continue;
    const s = m.index + (m[0].length - cap.length); // val is a prefix of cap, and cap ends m[0]
    spans.push({ start: s, end: s + val.length, type: "PERSON", value: val, via: "label" });
  }
  FIELD_NAME.lastIndex = 0;
  while ((m = FIELD_NAME.exec(text)) !== null) {
    const cap = m[1] || "";
    // explicit=true: a field name is as deliberate a declaration as "Name:" is, so a lowercase
    // value ("jennifer") is still a name.
    const val = validName(cap, true); if (!val) continue;
    const s = m.index + (m[0].length - cap.length);
    spans.push({ start: s, end: s + val.length, type: "PERSON", value: val, via: "field" });
  }
  MAIDEN.lastIndex = 0;
  while ((m = MAIDEN.exec(text)) !== null) {
    const val = m[1];
    const s2 = m.index + (m[0].length - val.length);
    spans.push({ start: s2, end: s2 + val.length, type: "PERSON", value: val, via: "label" });
  }
  FIELD_ID.lastIndex = 0;
  while ((m = FIELD_ID.exec(text)) !== null) {
    const val = m[1];
    // An identifier has at least one digit; without that, "policy: renewal" becomes an ID.
    if (!val || !/\d/.test(val)) continue;
    const s2 = m.index + (m[0].length - val.length);
    spans.push({ start: s2, end: s2 + val.length, type: "ID", value: val, via: "field" });
  }
  FIELD_DOB.lastIndex = 0;
  while ((m = FIELD_DOB.exec(text)) !== null) {
    const val = m[1]; if (!val || !validDate(val)) continue;
    const s = m.index + (m[0].length - val.length);
    spans.push({ start: s, end: s + val.length, type: "DOB", value: val, via: "checksum" });
  }
  LABEL_ID.lastIndex = 0;
  while ((m = LABEL_ID.exec(text)) !== null) {
    const val = m[1]; if (!val || !/\d/.test(val)) continue;
    const s = m.index + (m[0].length - val.length);
    spans.push({ start: s, end: s + val.length, type: "ID", value: val, via: "label" });
  }
  LABEL_DOB.lastIndex = 0;
  while ((m = LABEL_DOB.exec(text)) !== null) {
    const val = m[1]; if (!val || !validDate(val)) continue;
    const s = m.index + (m[0].length - val.length);
    spans.push({ start: s, end: s + val.length, type: "DOB", value: val, via: "checksum" });
  }
  return spans;
}

// ------------------------------ Config ------------------------------

export const DEFAULT_CONFIG = {
  // Which built-in detectors are active.
  detectors: {
    EMAIL: true,
    CREDIT_CARD: true,
    SA_ID: true,
    SSN: true,
    PHONE: true,
    IPV4: true,
    IBAN: true,
    // Extended coverage — all checksum-/format-gated, so on by default (low false-positive risk).
    IPV6: true,
    MAC: true,
    VIN: true,
    PAN_INDIA: true,
    NINO_UK: true,
    AADHAAR: true,
    ETH_ADDRESS: true,
    BTC_ADDRESS: true,
    STREET_ADDRESS: true,
    // PO_BOX is deliberately absent: it emits STREET_ADDRESS tokens, and _activeDetectors runs a
    // detector when EITHER its key or its emitted type is on, so it already rides the street
    // switch. A PO_BOX: false here would read as "off" while it is on.
    //
    // GPS does not ride anything, so without an entry it was simply unreachable. Off rather
    // than on: turning it on for every existing workspace changes what their documents look
    // like, which is a product decision, not a bug fix. The catalogue makes it a choice.
    GPS: false,
    PERSON: false, // heuristic — off by default; clients opt in
    // Credentials (API keys, private keys, seed phrases, JWTs, connection strings, labelled
    // secrets). One switch for the whole family. On by default: every pattern is provider-
    // registered or structurally rigid, so the false-positive risk is lower than PHONE's.
    SECRETS: true,
  },
  // PERSON detection mode when enabled: "strict" | "balanced".
  personMode: "balanced",
  // Literal terms (names, project codenames, client identifiers) to always mask.
  customTerms: [],
  // Never-mask allowlist: values confirmed "not PII" (false positives). Detection still
  // runs but these are dropped before masking. Populated by the leak-audit "Not PII" action.
  allowTerms: [],
  // Extra user regexes: [{ type, pattern, flags }].
  customPatterns: [],
  // Token delimiters. Double brackets keep collisions with real text near zero.
  tokenPrefix: "[",
  tokenSuffix: "]",
};

// ------------------------------ Session ------------------------------


/** How many characters two strings share at their touching ends. */
function sharedEnd(a, b) {
  let n = 0;
  while (n < a.length && n < b.length && a[a.length - 1 - n] === b[b.length - 1 - n]) n++;
  return n;
}
function sharedStart(a, b) {
  let n = 0;
  while (n < a.length && n < b.length && a[n] === b[n]) n++;
  return n;
}
const escToken = (t) => t.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
/** Context kept either side of a replacement — enough to tell one site from another. */
const SITE_CONTEXT = 40;
/** Matching context required before a site's surface form beats the canonical value. */
const SITE_MIN_MATCH = 10;


// ---------------------------- confusable normalisation ----------------------------
/**
 * Characters that hide a value from a shape detector while changing nothing a reader sees.
 *
 * Two families, and they need different treatment:
 *
 *   INVISIBLE — zero-width space/non-joiner/joiner, word joiner, byte-order mark, and the soft
 *   hyphen Word inserts. These render as nothing. Dropping them for the purposes of matching is
 *   what lets "4111<ZWSP>1111<ZWSP>1111<ZWSP>1111" be seen as the card it is.
 *
 *   FULL-WIDTH and non-Latin digit forms. Ordinary characters in Japanese, Chinese and Arabic
 *   text, not exotic ones, and a phone number written in them is still a phone number.
 *
 * Crucially this is used to FIND, never to rewrite. Detection runs against the normalised copy;
 * the spans are mapped back and the ORIGINAL text is what gets replaced, so the token covers the
 * whole obfuscated run and rehydrate still returns the input byte for byte. Normalising the
 * document itself would be a different bug wearing this one's clothes.
 */
const INVISIBLE_CODES = new Set([0x00ad, 0x200b, 0x200c, 0x200d, 0x2060, 0xfeff]);
/** First code point of each contiguous run of ten digits we understand. */
const DIGIT_BASES = [0x0660, 0x06f0, 0x0966, 0x09e6, 0x0a66, 0x0ae6, 0x0b66, 0x0be6, 0x0c66,
  0x0ce6, 0x0d66, 0x0e50, 0x0ed0, 0x0f20, 0x1040, 0x17e0, 0x1810, 0xff10];
/** Cheap gate: the overwhelming majority of documents contain none of this. */
/**
 * Written with \u escapes rather than the characters themselves, on purpose.
 *
 * This file is served to a page as a classic script. Without an explicit charset the browser
 * decodes it as Latin-1, every literal non-ASCII character in a regex turns into mojibake, and
 * the class becomes `Range out of order` — a SyntaxError that takes the whole engine down and
 * shows up as "the extension did not boot" rather than as anything about encoding. Escapes are
 * pure ASCII and cannot be mis-decoded.
 */
const CONFUSABLE_RE = /[\u00AD\u200B-\u200D\u2060\uFEFF\u3000\uFF01-\uFF5E\u0660-\u0669\u06F0-\u06F9\u0966-\u096F\u09E6-\u09EF\u0A66-\u0A6F\u0AE6-\u0AEF\u0B66-\u0B6F\u0BE6-\u0BEF\u0C66-\u0C6F\u0CE6-\u0CEF\u0D66-\u0D6F\u0E50-\u0E59\u0ED0-\u0ED9\u0F20-\u0F29\u1040-\u1049\u17E0-\u17E9\u1810-\u1819]/;

/**
 * A normalised copy plus an index back to the original.
 *
 * `idx[i]` is the original offset of normalised character i, so a match at [s, e) in the copy is
 * [idx[s], idx[e - 1] + 1) in the original. Every character maps to one or zero output characters,
 * never more, which is what keeps that arithmetic exact.
 *
 * Returns null when there is nothing to do, so the common path costs one regex test.
 */
export function normalizeConfusables(text) {
  if (typeof text !== "string" || !CONFUSABLE_RE.test(text)) return null;
  let norm = "";
  const idx = [];
  for (let i = 0; i < text.length; i++) {
    const code = text.charCodeAt(i);
    if (INVISIBLE_CODES.has(code)) continue;                       // renders as nothing; matches as nothing
    let out = text[i];
    if (code >= 0xff01 && code <= 0xff5e) out = String.fromCharCode(code - 0xfee0);  // full-width ASCII
    else if (code === 0x3000) out = " ";                                            // ideographic space
    else {
      for (const b of DIGIT_BASES) {
        if (code >= b && code <= b + 9) { out = String.fromCharCode(48 + code - b); break; }
      }
    }
    norm += out;
    idx.push(i);
  }
  return { norm, idx };
}

export class RedactionSession {
  constructor(config = DEFAULT_CONFIG) {
    this.config = { ...DEFAULT_CONFIG, ...config };
    this.counters = {}; // type -> running counter
    this.byKey = new Map(); // `${type}::${norm}` -> token
    this.tokenToOriginal = new Map(); // token -> original value
    this.originalType = new Map();
    this.tokenSites = new Map();   // token -> [{surface, before, after}] seen for it
    this.certain = new Set();      // values a field name or a checksum established, lowercased    // original value -> type, so the sweep knows what it seeks
    this.counts = {}; // type -> how many DISTINCT values masked
    this.total = 0; // total distinct values masked
    // Never-mask allowlist: values an admin marked "not PII" (false positives). Detection
    // still runs, but any hit whose value is on the list is dropped before masking, so the
    // engine "learns" to stop flagging it. Matched case-insensitively on the trimmed value.
    this.allow = new Set((this.config.allowTerms || []).map((t) => String(t).trim().toLowerCase()).filter(Boolean));
    // Human-in-the-loop review: finding ids a reviewer rejected in a preview ("not PII here").
    this.reject = new Set(this.config.rejectValues || []);
    // Tuning knobs (competitor parity): confidence floor and per-type instance thresholds.
    this.minConfidence = typeof this.config.minConfidence === "number" ? this.config.minConfidence
      : (this.config.minConfidenceLevel ? (LEVEL_SCORE[this.config.minConfidenceLevel] || 0) : 0);
    this.instanceThreshold = this.config.instanceThreshold || null;
    // Findings from the last redactText/redactSpans call — one entry per DISTINCT value.
    this.findings = new Map(); // id -> { id, type, value, level, confidence, reason, count, token }
  }

  /** Record a match in the findings map (used by review/preview UIs). */
  _note(m, token) {
    const f = this.findings.get(m.id);
    if (f) { f.count++; return; }
    this.findings.set(m.id, { id: m.id, type: m.type, value: m.value, level: m.level, confidence: m.confidence, reason: m.reason, count: 1, token });
  }
  /** Distinct findings, highest-risk-to-review first (lowest confidence surfaces at the top). */
  findingList() {
    return [...this.findings.values()].sort((a, b) => a.confidence - b.confidence || a.type.localeCompare(b.type));
  }

  _activeDetectors() {
    const out = [];
    for (const [type, det] of Object.entries(BUILTIN_DETECTORS)) {
      if (this.config.detectors?.[type] || this.config.detectors?.[det.type]) out.push(det);
    }
    for (const p of this.config.customPatterns || []) {
      const source = p.pattern || p.regex; // accept either field name
      if (!source) continue;
      const flags = (p.flags || "").includes("g") ? p.flags : (p.flags || "") + "g"; // always global for matchAll
      try {
        // A rule for ONE LINE of a block the reviewer marked (see _customTermMatches) is flagged, so
        // what it masks is not then hunted through the rest of the document as a known value.
        out.push({ type: p.type || p.name || "CUSTOM", re: new RegExp(source, flags), via: "custom", wholeLine: source.startsWith(WHOLE_LINE_PREFIX) });
      } catch {
        /* skip invalid user regex */
      }
    }
    return out;
  }

  /**
   * A term matches however the document breaks it across lines.
   *
   * A reviewer who highlights a signature block ("Tshepiso Vermaak\nSenior Talent Partner") is
   * pointing at text that the document lays out over several lines, and a space in the term never
   * matched the line break in the document, so the block was masked nowhere. Any run of whitespace
   * in a term now matches any run in the text.
   *
   * That is not enough for Word. A .docx is redacted one paragraph at a time, so a block that is
   * three paragraphs is never seen whole. Each line of a multi-line term is therefore a term of its
   * own too, but only where it is a WHOLE line: "Capacity: Director" on a line by itself is the
   * signature block wherever it appears, while "director" in the middle of a sentence is not.
   */
  _customTermMatches(text) {
    const terms = (this.config.customTerms || []).filter(Boolean);
    if (!terms.length) return [];
    const lit = (t) => t.trim().replace(/[.*+?^${}()|[\]\\]/g, "\\$&").replace(/\s+/g, "\\s+");
    const lines = terms.flatMap((t) => (/\n/.test(t.trim()) ? t.split(/\r?\n/).map((l) => l.trim()).filter((l) => l.length > 2) : []));
    const escaped = terms
      .slice()
      .sort((a, b) => b.length - a.length)
      .map(lit);
    const whole = lines.sort((a, b) => b.length - a.length).map((l) => `${WHOLE_LINE_PREFIX}${lit(l)}(?=[ \\t\\u00a0]*(?:\\r?\\n|$))`);
    const re = new RegExp(`(?<![\\w])(?:${[...escaped, ...whole].join("|")})(?![\\w])`, "gi");
    const full = new RegExp(`^(?:${escaped.join("|")})$`, "i");
    const matches = [];
    for (const m of text.matchAll(re)) {
      // One line of a block is masked where it stands, and is not then treated as a known value:
      // "Director" is personal on the signature line and nowhere else.
      const wholeLine = !full.test(m[0]);
      matches.push({ start: m.index, end: m.index + m[0].length, type: "CUSTOM", value: m[0], via: "term", ...(wholeLine ? { wholeLine } : {}) });
    }
    return matches;
  }

  /** Assign (or reuse) a stable token for a given type+value. */
  tokenFor(type, value) {
    const norm = value.trim().toLowerCase();
    const key = `${type}::${norm}`;
    const existing = this.byKey.get(key);
    if (existing) return existing;
    this.counters[type] = (this.counters[type] || 0) + 1;
    const token = `${this.config.tokenPrefix}${type}_${this.counters[type]}${this.config.tokenSuffix}`;
    this.byKey.set(key, token);
    this.tokenToOriginal.set(token, value);
    this.originalType.set(value, type);
    this.counts[type] = (this.counts[type] || 0) + 1;
    this.total += 1;
    return token;
  }

  /** Redact a single string, returning the masked text. */
  /** Detected, overlap-resolved, non-overlapping matches [{start,end,type,value}], sorted. */
  /**
   * Find values ALREADY known to be personal, re-punctuated or re-encoded, anywhere in `text`.
   *
   * `seen` is what the shape detectors just found in this same text, so a value can be swept from a
   * URL later in the payload even on the very first call. Values carried from earlier calls come
   * from `tokenToOriginal`, which is what makes this work for the wrapper's leaf-by-leaf walk —
   * with the caveat that a URL redacted BEFORE the name has ever been seen cannot be swept. In
   * practice Greenhouse sends first_name and last_name ahead of the attachments, and a whole-record
   * redaction sees everything at once.
   */
/**
   * Token-shaped text that came from UPSTREAM, not from us.
   *
   * A candidate writes "[PERSON_1]" in their cover letter. It is not PII, so it reaches the model
   * verbatim — and now the model is holding a string indistinguishable from a token we issued. When
   * it sends that text back, rehydration substitutes a real identity into attacker-controlled text.
   * Anything a candidate can type into an ATS record can make the shield inject the names it holds
   * into an arbitrary upstream write.
   *
   * So a token-shaped string in source data gets a token OF ITS OWN. The model sees [LITERAL_1],
   * which stands for the characters "[PERSON_1]" and rehydrates back to exactly those characters.
   * The forged token never reaches the model, the real one is never collided with, and the payload
   * still round-trips byte-for-byte.
   */
  _tokenLookalikes(text) {
    const pre = this.config.tokenPrefix ?? "[";
    const suf = this.config.tokenSuffix ?? "]";
    if (!pre || !suf) return [];
    const re = new RegExp(`${escToken(pre)}[A-Z][A-Z0-9_]*_\\d+${escToken(suf)}`, "g");
    const out = [];
    for (const m of text.matchAll(re)) {
      out.push({ start: m.index, end: m.index + m[0].length, type: "LITERAL", value: m[0], via: "token_literal" });
    }
    return out;
  }

/**
   * Values written so that no detector can see them: percent-encoded, HTML-entity encoded, or
   * spelled out as "name [at] example [dot] com" the way a scraped CV writes an address.
   *
   * Each region is decoded, run past the ordinary detectors, and — if anything is found — masked
   * WHOLE. Sweeping for the decoded value instead does not work: "+27825550143" appears nowhere in
   * "phone=%2B27825550143", and the bare digits are butted against the B of %2B, so no bounded
   * pattern can reach them.
   */
  _base64Regions(text) {
    if (!text || text.length < 24) return [];
    const spans = [];
    for (const m of text.matchAll(/(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{24,}={0,2}(?![A-Za-z0-9+/=])/g)) {
      let decoded;
      try { decoded = Buffer.from(m[0], "base64").toString("utf8"); } catch { continue; }
      if (!decoded || decoded.length < 8) continue;
      const printable = (decoded.match(/[\x20-\x7e\n\r\t]/g) || []).length / decoded.length;
      if (printable < 0.95) continue;                       // binary: an image, not a document
      let found = false;
      for (const det of this._activeDetectors()) {
        det.re.lastIndex = 0;
        for (const hit of decoded.matchAll(det.re)) {
          if (det.validate && !det.validate(hit[0])) continue;
          found = true; break;
        }
        if (found) break;
      }
      if (!found) continue;
      spans.push({ start: m.index, end: m.index + m[0].length, type: "SECRET", value: m[0], via: "structural" });
    }
    return spans;
  }

  _encodedRegions(text) {
    if (!text || text.length < 4) return [];
    const spans = [];
    const regions = [];
    for (const m of text.matchAll(/[A-Za-z0-9%+._~@-]*(?:%[0-9A-Fa-f]{2}|&#\d{2,4};)[A-Za-z0-9%+._~@;#&-]*/g)) {
      let decoded;
      try { decoded = decodeURIComponent(m[0].replace(/&#(\d{2,4});/g, (_, d) => String.fromCharCode(Number(d)))); }
      catch { continue; }
      if (decoded !== m[0]) regions.push({ start: m.index, end: m.index + m[0].length, decoded });
    }
    for (const m of text.matchAll(/[A-Za-z0-9._%+-]+(?:\s*[[(]\s*at\s*[\])]\s*|\s+at\s+)[A-Za-z0-9.-]+(?:(?:\s*[[(]\s*dot\s*[\])]\s*|\s+dot\s+)[A-Za-z0-9-]+)+/gi)) {
      const decoded = m[0]
        .replace(/\s*[[(]\s*at\s*[\])]\s*|\s+at\s+/gi, "@")
        .replace(/\s*[[(]\s*dot\s*[\])]\s*|\s+dot\s+/gi, ".");
      regions.push({ start: m.index, end: m.index + m[0].length, decoded });
    }
    for (const r of regions) {
      let best = null;
      for (const det of this._activeDetectors()) {
        det.re.lastIndex = 0;
        for (const hit of r.decoded.matchAll(det.re)) {
          if (det.validate && !det.validate(hit[0])) continue;
          if (!best || hit[0].length > best.length) best = { length: hit[0].length, type: det.type };
        }
      }
      if (!best) continue;
      // The DECODED value, not the encoded characters. Using the raw region minted a second token
      // for an address already masked in plain form two fields earlier — one candidate, two tokens.
      // The site record keeps the encoded surface so rehydration puts back exactly what was there.
      spans.push({ start: r.start, end: r.end, type: best.type, value: r.decoded, via: "structural" });
    }
    return spans;
  }

  _sweepKnown(text, seen) {
    if (!text || text.length < 4) return [];
    /** [value, type] pairs worth sweeping for. */
    const known = new Map();
    // PERSON and EMAIL only. Those are the values that re-identify someone when they turn up
    // re-punctuated in a URL or a filename. Sweeping the others is actively wrong: a date splits
    // into ["1990","01","15"], whose "first two tokens" variant happily eats the "1990-01" out of
    // an unrelated `created_at`, and a phone or an ID is already found by its own shape wherever
    // it appears.
    for (const [, original] of this.tokenToOriginal) {
      const t = this.originalType.get(original);
      // PERSON and EMAIL always: those are the values that re-identify someone when they turn up
      // re-punctuated. Anything ESTABLISHED by a field name or a checksum also propagates — a tax
      // number masked under `tax_number` and left standing in the note below it is the same defect.
      //
      // DOB is the exception even when established. A date is genuinely ambiguous: the same string
      // is a birth date in one field and a row timestamp in the next, and masking `created_at`
      // because it happens to match is over-masking a system field.
      const sureVal = t !== "DOB" && this.certain.has(String(original).trim().toLowerCase());
      if (t === "PERSON" || t === "EMAIL" || sureVal) known.set(original, t || "PERSON");
    }
    for (const m of seen) if (m.type === "PERSON" || m.type === "EMAIL") known.set(m.value, m.type);
    // A value can exist ONLY in disguised form — an attachment URL carrying
    // `jenn%40acme.co.za` and a filename `Jennifer_Testcase_CV.pdf`, with the plain address and
    // the plain name nowhere in the payload. Nothing is "already known" to sweep for, so undo the
    // two disguises and let the ordinary detectors look at the result. Whatever they find is then
    // swept back onto the ORIGINAL text in its disguised form.
    for (const v of this._unmasked(text)) known.set(v[0], v[1]);
    if (!known.size) return [];
    // PERSON first. Where a name and an email built from that name both explain the same slug,
    // equal-length spans are settled by order, and "[PERSON_1]" is the honest label for a name.
    const ordered = [...known].sort((a, b) => (a[1] === "PERSON" ? 0 : 1) - (b[1] === "PERSON" ? 0 : 1));

    // An ATS splits the name across first_name and last_name, so the session holds two single-token
    // values and no full name to look for. Pair them back up. The span is attributed to the
    // SURNAME's value so it reuses that token rather than inventing a third identity for the
    // same person.
    const singles = ordered.filter(([v, t]) => t === "PERSON" && valueTokens(v).length === 1).slice(0, 8);
    const pairs = [];
    for (const [a] of singles) {
      for (const [b] of singles) {
        if (a === b) continue;
        const [ta, tb] = [valueTokens(a)[0], valueTokens(b)[0]];
        if (!ta || !tb || tb.length < 3) continue;
        // The FIRST half must be a name we actually know. Without this the sweep will pair any two
        // single-word values it has ever seen and treat the combination as a person: on a real
        // contract it learned "Independent" and "Contractor" separately and then masked the
        // heading "INDEPENDENT CONTRACTOR", which destroys the document it is supposed to protect.
        if (!FIRST_NAMES.has(ta)) continue;
        const bd = (body, ci) =>
          ({ re: new RegExp(`(?<![A-Za-z0-9])${body}(?![A-Za-z0-9])`, ci ? "gi" : "g"), urlOnly: ci, type: "PERSON", value: b });
        for (const ci of [false, true]) pairs.push(bd(`${escRe(ta)}${SEP}${escRe(tb)}[0-9]*`, ci));
        if (tb.length >= 5) for (const ci of [false, true]) pairs.push(bd(`${escRe(ta[0])}${SEP}${escRe(tb)}[0-9]*`, ci));
      }
    }

    // Where a lone surname is allowed to match.
    let urlZones = null;
    const inUrlZone = (s, e) => {
      if (urlZones === null) {
        urlZones = [];
        URLISH.lastIndex = 0;
        for (const u of text.matchAll(URLISH)) urlZones.push([u.index, u.index + u[0].length]);
      }
      return urlZones.some(([a, b]) => s >= a && e <= b);
    };

    const out = [];
    const record = (m, type, value, urlOnly) => {
      if (urlOnly && !inUrlZone(m.index, m.index + m[0].length)) return;
      if (m[0] === value) return;   // the plain form is the detectors' job
      out.push({ start: m.index, end: m.index + m[0].length, type, value, via: "known_value", swept: m[0] });
    };
    for (const pat of pairs) {
      pat.re.lastIndex = 0;
      for (const m of text.matchAll(pat.re)) record(m, pat.type, pat.value, pat.urlOnly);
    }
    for (const [value, type] of ordered) {
      // Never sweep for a value the caller has told us is not PII.
      if (this.allow.has(String(value).trim().toLowerCase())) continue;
      const sure = this.certain.has(String(value).trim().toLowerCase());
      const pats = sweepPatterns(value, type);
      // Even a declared value needs some substance before it is chased through the payload. "Li" is
      // a surname and also a syllable in a hundred URLs, and propagating it swept it out of a path.
      if (sure && String(value).replace(/[^\p{L}\p{N}]/gu, "").length >= 3) {
        // The value itself, however it is cased. This is the propagation step: masked once for a
        // reason we trust, masked everywhere it appears.
        pats.push({ re: new RegExp(`(?<![A-Za-z0-9])${escRe(String(value))}(?![A-Za-z0-9])`, "giu"), urlOnly: false });
        if (type === "PERSON") {
          for (const part of String(value).split(/[\s]+/)) {
            const bare = part.replace(/[^\p{L}\p{M}'’-]/gu, "");
            if (bare.length < 3 || SWEEP_STOPWORDS.has(bare.toLowerCase())) continue;
            pats.push({ re: new RegExp(`(?<![\\p{L}\\p{N}])${escRe(bare)}(?![\\p{L}\\p{N}])`, "giu"), urlOnly: false });
          }
        }
      }
      for (const { re, urlOnly, fragment } of pats) {
        re.lastIndex = 0;
        for (const m of text.matchAll(re)) {
          if (urlOnly && !sure && !inUrlZone(m.index, m.index + m[0].length)) continue;
          // A lone surname swept off an ESTABLISHED email, outside any URL. Masking it is right:
          // a "Surname" column beside an "Email" column is the same person either way. Calling it
          // that email is not, and the damage shows up on the way back — a real user list restored
          // [EMAIL_86] over twelve one-word cells as the full address, so a spreadsheet that held
          // a surname came back holding sipho.nkosi@corp.example. Give the fragment its own PERSON
          // identity: same coverage, and the token now says what it actually stands for.
          //
          // Inside a URL the fragment stays with the address, where it is genuinely part of the
          // slug and tokenSites already restores the form that was there.
          const asName = fragment && type === "EMAIL" && !inUrlZone(m.index, m.index + m[0].length);
          if (asName) {
            out.push({
              start: m.index, end: m.index + m[0].length, type: "PERSON", value: m[0],
              via: "established", swept: m[0], sure,
            });
            continue;
          }
          // Normally the plain form is the detectors' job and this pass only handles variants. But
          // when the value is ESTABLISHED — a field name said so — the detectors demonstrably do
          // not always find it in prose: "Art Vandelay" under `name` was masked, and the same two
          // words in `notes` came back as "Art [PERSON_1]" because only the surname pattern hit.
          // Overlapping spans are dropped against `seen` below, so this cannot double-count.
          if (m[0] === value && !sure) continue;
          out.push({
            start: m.index, end: m.index + m[0].length, type, value,
            via: sure ? "established" : "known_value", swept: m[0], sure,
          });
        }
      }
    }
    // A swept span that OVERLAPS a real detection is a phantom: the "first two tokens" variant of
    // an email matches "a@b" inside the "a@b.com" a detector already found. Overlap resolution
    // discards it from the output anyway — but only AFTER counting, so every occurrence was being
    // counted twice and instanceThreshold fired on a single sighting. The sweep fills gaps; it
    // takes no ground the detectors already hold.
    // Drop phantoms — a variant that merely overlaps a real detection would otherwise be counted
    // before overlap resolution discards it, which doubled occurrence counts.
    //
    // An ESTABLISHED value is exempt from all but an exact duplicate. A tax number in a note was
    // overlapped by a PHONE candidate that was then itself thrown out by scoring, so filtering on
    // overlap alone discarded the one span that would have masked it and nothing took its place.
    return out.filter((sp) => (sp.sure
      // An established span CONTAINED in a detection the pass already made adds nothing: the
      // two-token variant of an email matches "a@b" inside the "a@b.com" already found, and
      // counting it made one sighting look like two and tripped a threshold of 2.
      ? !seen.some((m) => sp.start >= m.start && sp.end <= m.end)
      : !seen.some((m) => sp.start < m.end && m.start < sp.end)));
  }

  /**
   * Values that only appear percent-encoded, or joined by separators inside a URL or filename.
   * Returns [value, type] pairs for the sweep to look for in the original text.
   */
  _unmasked(text) {
    const found = [];
    const variants = [];
    if (/%[0-9A-Fa-f]{2}|&#\d{2,4};/.test(text)) {
      try { variants.push(decodeURIComponent(text)); } catch { /* malformed escape; skip */ }
      // HTML entities hide the same characters a percent-escape does.
      variants.push(text.replace(/&#(\d{2,4});/g, (_, d) => String.fromCharCode(Number(d))));
    }
    // Separators become spaces, but ONLY inside URL/path/filename text. Doing this to prose would
    // invent names out of hyphenated words.
    URLISH.lastIndex = 0;
    for (const u of text.matchAll(URLISH)) {
      if (/[_\-]/.test(u[0])) variants.push(u[0].replace(/[_\-]+/g, " "));
    }
    // An obfuscated address is still an address, and this is the standard way CVs write one.
    if (/\[\s*(?:at|dot)\s*\]|\(\s*(?:at|dot)\s*\)|\s+at\s+\S+\s+dot\s+/i.test(text)) {
      variants.push(text
        .replace(/\s*[[(]\s*at\s*[\])]\s*/gi, "@").replace(/\s+at\s+(?=\S+\s+dot\s+)/gi, "@")
        .replace(/\s*[[(]\s*dot\s*[\])]\s*/gi, ".").replace(/\s+dot\s+/gi, "."));
    }
    for (const v of variants) {
      if (!v || v === text) continue;
      for (const det of this._activeDetectors()) {
        det.re.lastIndex = 0;
        for (const m of v.matchAll(det.re)) {
          if (det.validate && !det.validate(m[0])) continue;
          found.push([m[0], det.type]);
        }
      }
      if (this.config.detectors?.PERSON) {
        for (const p of detectPersons(v, this.config.personMode || "balanced")) found.push([p.value, "PERSON"]);
      }
    }
    return found;
  }

  /**
   * Detection, with obfuscated values seen through.
   *
   * When the text carries confusable characters, detection runs against a normalised copy and the
   * spans are translated back, so everything downstream — redaction, sites, rehydrate — works in
   * ORIGINAL coordinates and the document is never rewritten. `value` is deliberately the original
   * substring rather than the normalised one, so what is put back is exactly what was there.
   */
  _chosen(text) {
    const n = normalizeConfusables(text);
    if (!n) return this._chosenIn(text);
    const out = [];
    for (const m of this._chosenIn(n.norm)) {
      if (m.end <= m.start) continue;
      const start = n.idx[m.start];
      const end = n.idx[m.end - 1] + 1;
      if (start === undefined || end === undefined) continue;
      out.push({ ...m, start, end, value: text.slice(start, end) });
    }
    return out;
  }

  _chosenIn(text) {
    let matches = [];
    for (const det of this._activeDetectors()) {
      det.re.lastIndex = 0;
      for (const m of text.matchAll(det.re)) {
        const value = m[0];
        if (det.validate && !det.validate(value)) continue;
        let via = det.via || VIA_BY_TYPE[det.type] || "shape";
        // An SA ID whose check digit does not match is still an ID, but it is not a verified one —
        // report it as a shape match so its confidence and its stated reason both tell the truth.
        const weak = det.type === "SA_ID" && !SA_ID_LAST_LUHN;
        if (weak) via = "sa_id_weak";
        // An IBAN that fails mod-97 is still masked, but it is not a verified one and must not
        // claim to be. "structural" means the format cannot be hit by accident; this one was.
        if (det.type === "IBAN") via = IBAN_LAST_MOD97 ? "checksum" : "shape";
        // Inside a URL or a query string a VIN-shaped run is a path segment or a parameter, unless
        // its check digit says otherwise.
        if (det.type === "VIN") via = VIN_LAST_TIER === "checksum" || !/[\/=?#&]/.test(text[m.index - 1] || "") ? VIN_LAST_TIER : "vin_weak";
        matches.push({ start: m.index, end: m.index + value.length, type: det.type, value, via, ...(det.wholeLine ? { wholeLine: true } : {}) });
      }
    }
    matches = matches.concat(this._tokenLookalikes(text));
    matches = matches.concat(this._encodedRegions(text));
    matches = matches.concat(this._base64Regions(text));
    matches = matches.concat(this._customTermMatches(text));
    matches = matches.concat(detectLabeled(text)); // always on — labelled PII auto-pickup
    matches = matches.concat(detectTabular(text));  // column headers and adjacent label cells
    if (this.config.detectors?.SECRETS !== false) matches = matches.concat(detectSecrets(text));
    if (this.config.detectors?.PERSON) {
      matches = matches.concat(detectPersons(text, this.config.personMode || "balanced"));
    }
    // AFTER person detection, not before: the sweep looks for values already identified in this
    // same text, and running it first meant it never saw the names. A profile slug then got
    // attributed to the candidate's EMAIL — masked, but labelled as the wrong kind of thing.
    // A value this payload has already ESTABLISHED — a field name declared it, or a checksum proved
    // it — is not a candidate for the scorer to argue with. Upgrade the evidence on the match that
    // is already here rather than adding a second span for the same characters: a duplicate span
    // would be dropped as a phantom, and the original was about to be downranked out of existence
    // by the words next to it ("SARS tax ref 0123456789").
    // Register certainty BEFORE the sweep, not only in the scoring pass below it. Within a single
    // call the sweep runs first, so a value declared by a label in THIS text — `"name": "marcus
    // delacroix"` inside a serialised record — conferred nothing until the next call, and the same
    // string three lines down was left standing.
    for (const m of matches) {
      if (!CERTAIN_VIA.has(m.via) || m.wholeLine) continue;
      if (m.type === "PERSON" && !hasKnownGivenName(m.value)) continue;
      this.certain.add(String(m.value).trim().toLowerCase());
    }
    if (this.certain.size) {
      for (const m of matches) {
        if (m.via === "established") continue;
        if (!this.certain.has(String(m.value).trim().toLowerCase())) continue;
        // Do not flatten evidence that is already strong. A LABEL declared the type as well as the
        // value, and overwriting it lost that: `"tax_number": "0123456789"` tied with the phone
        // detector on the same characters and came back as [PHONE_1].
        if (CERTAIN_VIA.has(m.via)) continue;
        m.via = "established";
        // And take the type the record itself gave it. A tax number matched by the PHONE detector
        // in a note is still a tax number: the field it came from said so, and reporting it as a
        // phone would put the wrong label in front of a reviewer and in the Leak Audit.
        const declared = this.originalType.get(m.value) || this.originalType.get(String(m.value).trim());
        if (declared && declared !== m.type) { m.type = declared; m.id = findingId(declared, m.value); }
      }
    }
    matches = matches.concat(this._sweepKnown(text, matches));
    matches = dropInsideBase64(text, matches);
    matches = avoidJsonEscapes(text, matches);
    // Score every match from ITS OWN evidence — how it was found, what checksum passed, and the
    // words around it — not a static number keyed on the type. A match whose evidence does not
    // clear the floor (an order number after "order", a lowercase phrase after "name") is dropped
    // here, before it can reach a token or the Leak Audit. This is the fix for "behind it".
    const scored = [];
    for (const m of matches) {
      const c = scoreMatch(m, text);
      if (!c) continue; // evidence too weak to report at all
      m.confidence = c.confidence; m.level = c.level; m.reason = c.reason;
      m.id = findingId(m.type, m.value);
      if (CERTAIN_VIA.has(m.via) && !m.wholeLine && !(m.type === "PERSON" && !hasKnownGivenName(m.value))) {
        this.certain.add(String(m.value).trim().toLowerCase());
      }
      scored.push(m);
    }
    matches = scored;
    // Drop allowlisted values (confirmed not-PII) before masking.
    if (this.allow.size) matches = matches.filter((m) => !this.allow.has(String(m.value).trim().toLowerCase()));
    // Human review: values explicitly rejected in a preview stay in the clear.
    if (this.reject.size) matches = matches.filter((m) => !this.reject.has(m.id));
    // Confidence threshold (tuning knob — mirrors Purview's "raise the confidence level").
    if (this.minConfidence > 0) matches = matches.filter((m) => m.confidence >= this.minConfidence);
    // Instance-count threshold: only flag a type once it appears at least N times.
    if (this.instanceThreshold) {
      // Count OCCURRENCES, not candidate spans. Two passes can propose the same characters — a
      // detector and the known-value sweep both find one address — and counting each proposal made
      // a single sighting look like two, tripping a threshold of 2 on one email.
      const seen = {};
      const at = new Set();
      for (const m of matches) {
        const k = `${m.type}:${m.start}:${m.end}`;
        if (at.has(k)) continue;
        at.add(k);
        seen[m.type] = (seen[m.type] || 0) + 1;
      }
      matches = matches.filter((m) => (seen[m.type] || 0) >= (this.instanceThreshold[m.type] || 1));
    }
    if (!matches.length) return [];
    // Resolve overlaps: sort by start, then by precedence, then by length.
    matches.sort((a, b) => {
      if (a.start !== b.start) return a.start - b.start;
      const pa = precedenceOf(a);
      const pb = precedenceOf(b);
      if (pa !== pb) return pb - pa;
      return b.end - a.end;
    });
    const chosen = [];
    let lastEnd = -1;
    for (const m of matches) {
      if (m.start >= lastEnd) { chosen.push(m); lastEnd = m.end; }
    }
    return chosen;
  }

  redactText(text) {
    if (typeof text !== "string" || text.length === 0) return text;
    const chosen = this._chosen(text);
    if (!chosen.length) return text;
    let out = "";
    let cursor = 0;
    for (const m of chosen) {
      out += text.slice(cursor, m.start);
      const token = this.tokenFor(m.type, m.value);
      this._note(m, token);
      this._site(token, text, m.start, m.end);
      out += token;
      cursor = m.end;
    }
    out += text.slice(cursor);
    return out;
  }
  /**
   * Redact ONE VALUE that arrived under a KEY, for callers walking structured data leaf by leaf.
   *
   * Such a caller never has the key and the value in one string, so `redactText("Jennifer")` is all
   * it can ask — and that is unanswerable, because a given name has no shape. This puts the key
   * back: it detects against `full name: Jennifer`, keeps only the spans that land inside the value,
   * and returns the value alone. The probe is scaffolding and never reaches the caller.
   *
   * Keys we don't recognise fall through to plain text redaction, so shape-backed values (an email
   * under `value`, a phone under anything at all) are caught exactly as before.
   */
/**
   * Remember what a token replaced HERE, so it can be put back as it was found rather than as the
   * canonical value. Only sites whose surface differs from the canonical are worth keeping.
   */
  _site(token, text, start, end) {
    const surface = text.slice(start, end);
    // Canonical sites are recorded too, and that is not redundant: context has to be able to choose
    // the canonical form as well as a variant. Recording only variants meant `"last_name":"…"` was
    // matched against the filename site — `"last_name":"` and `"filename":"` share the seven
    // characters `name":"` — and a plain surname came back as `Marcus_Delacroix`.
    const before = text.slice(Math.max(0, start - SITE_CONTEXT), start);
    const after = text.slice(end, end + SITE_CONTEXT);
    const list = this.tokenSites.get(token) || [];
    if (list.some((s) => s.surface === surface && s.before === before && s.after === after)) return;
    if (list.length < 32) list.push({ surface, before, after });
    this.tokenSites.set(token, list);
  }

  redactField(key, value) {
    if (typeof value !== "string" || value.length === 0) return value;
    const label = fieldLabel(key);
    if (!label) return this.redactText(value);
    const prefix = `${label}: `;
    const probe = prefix + value;
    // Spans that touch the synthetic prefix are artefacts of the probe, not findings in the value.
    const chosen = this._chosen(probe).filter((m) => m.start >= prefix.length);
    // The KEY declared this value, which is a stronger claim than any heuristic makes. Record it as
    // established so every other occurrence in the payload follows, whatever its case — the same
    // string was being masked under `name` and left standing three fields later in `notes`.
    for (const m of chosen) this.certain.add(String(m.value).trim().toLowerCase());
    if (!chosen.length) return value;
    let out = "";
    let cursor = prefix.length;
    for (const m of chosen) {
      out += probe.slice(cursor, m.start);
      const token = this.tokenFor(m.type, m.value);
      this._note(m, token);
      this._site(token, probe, m.start, m.end);
      out += token;
      cursor = m.end;
    }
    return out + probe.slice(cursor);
  }

  /** Detect only — never rewrites the text. Powers "preview / dry-run" review flows. */
  scan(text) {
    if (typeof text !== "string" || !text) return [];
    for (const m of this._chosen(text)) this._note(m, `[${m.type}]`);
    return this.findingList();
  }

  /**
   * Like redactText but also returns the character spans → tokens, so callers can
   * edit PII in place inside a structured file (OOXML runs, PDF text) without
   * re-flowing everything. { redacted, spans: [{start,end,token,original,type}] }.
   */
  redactSpans(text) {
    if (typeof text !== "string" || text.length === 0) return { redacted: text, spans: [] };
    const chosen = this._chosen(text);
    const spans = [];
    let out = "";
    let cursor = 0;
    for (const m of chosen) {
      out += text.slice(cursor, m.start);
      const token = this.tokenFor(m.type, m.value);
      this._note(m, token);
      this._site(token, text, m.start, m.end);
      spans.push({ start: m.start, end: m.end, token, original: m.value, type: m.type, id: m.id, level: m.level, confidence: m.confidence, reason: m.reason });
      out += token;
      cursor = m.end;
    }
    out += text.slice(cursor);
    return { redacted: out, spans };
  }

/**
   * Replace tokens with what they stood for — the exact text at that site where we know it.
   *
   * A token can legitimately stand for several surface forms of one identity: "Delacroix" in a
   * name field, "mdelacroix87" in a handle, "Marcus_Delacroix" in a filename. Substituting the
   * canonical value everywhere is what turned every one of those write-backs into a dead URL, so
   * the surrounding text decides which form to restore, and the canonical value is the fallback
   * when the token appears somewhere we never saw.
   */
  rehydrate(text) {
    if (typeof text !== "string" || text.length === 0 || this.tokenToOriginal.size === 0) return text;
    const tokens = [...this.tokenToOriginal.keys()].sort((a, b) => b.length - a.length);
    if (!tokens.length) return text;
    const re = new RegExp(tokens.map(escToken).join("|"), "g");
    return text.replace(re, (tok, offset) => {
      const canonical = this.tokenToOriginal.get(tok);
      const sites = this.tokenSites.get(tok);
      if (!sites || !sites.length) return canonical;
      const before = text.slice(Math.max(0, offset - SITE_CONTEXT), offset);
      const after = text.slice(offset + tok.length, offset + tok.length + SITE_CONTEXT);
      let best = null;
      let bestScore = SITE_MIN_MATCH - 1;
      for (const s of sites) {
        const score = sharedEnd(before, s.before) + sharedStart(after, s.after);
        if (score > bestScore) { bestScore = score; best = s; }
      }
      return best ? best.surface : canonical;
    });
  }

}

// --------------------- Anthropic body walkers ---------------------

/** Redact a `system` field (string or array of text blocks). */
function redactSystem(system, session) {
  if (typeof system === "string") return session.redactText(system);
  if (Array.isArray(system)) {
    return system.map((b) =>
      b && b.type === "text" && typeof b.text === "string" ? { ...b, text: session.redactText(b.text) } : b
    );
  }
  return system;
}

/** Redact every string leaf in a tool_use input object. */
function redactDeep(node, session) {
  if (typeof node === "string") return session.redactText(node);
  if (Array.isArray(node)) return node.map((n) => redactDeep(n, session));
  if (node && typeof node === "object") {
    const out = {};
    for (const [k, v] of Object.entries(node)) out[k] = redactDeep(v, session);
    return out;
  }
  return node;
}

function redactContentBlock(block, session) {
  if (!block || typeof block !== "object") return block;
  switch (block.type) {
    case "text":
      return typeof block.text === "string" ? { ...block, text: session.redactText(block.text) } : block;
    case "tool_result": {
      if (typeof block.content === "string") return { ...block, content: session.redactText(block.content) };
      if (Array.isArray(block.content)) return { ...block, content: block.content.map((b) => redactContentBlock(b, session)) };
      return block;
    }
    case "tool_use":
      return block.input ? { ...block, input: redactDeep(block.input, session) } : block;
    default:
      return block; // images, documents, etc. pass through untouched
  }
}

function redactMessage(msg, session) {
  if (!msg || typeof msg !== "object") return msg;
  if (typeof msg.content === "string") return { ...msg, content: session.redactText(msg.content) };
  if (Array.isArray(msg.content)) return { ...msg, content: msg.content.map((b) => redactContentBlock(b, session)) };
  return msg;
}

/**
 * Redact an Anthropic /v1/messages request body.
 * Returns { body: redactedClone, session }.
 */
export function redactMessagesBody(body, config = DEFAULT_CONFIG, session) {
  session = session || new RedactionSession(config);
  if (!body || typeof body !== "object") return { body, session };
  const clone = { ...body };
  if (clone.system !== undefined) clone.system = redactSystem(clone.system, session);
  if (Array.isArray(clone.messages)) clone.messages = clone.messages.map((m) => redactMessage(m, session));
  return { body: clone, session };
}

/** Re-hydrate a non-streaming Anthropic response object in place (clone). */
export function rehydrateResponse(resp, session) {
  if (!resp || typeof resp !== "object" || !Array.isArray(resp.content)) return resp;
  const clone = { ...resp };
  clone.content = resp.content.map((b) => {
    if (b && b.type === "text" && typeof b.text === "string") return { ...b, text: session.rehydrate(b.text) };
    if (b && b.type === "tool_use" && b.input) return { ...b, input: rehydrateDeep(b.input, session) };
    return b;
  });
  return clone;
}

function rehydrateDeep(node, session) {
  if (typeof node === "string") return session.rehydrate(node);
  if (Array.isArray(node)) return node.map((n) => rehydrateDeep(n, session));
  if (node && typeof node === "object") {
    const out = {};
    for (const [k, v] of Object.entries(node)) out[k] = rehydrateDeep(v, session);
    return out;
  }
  return node;
}
