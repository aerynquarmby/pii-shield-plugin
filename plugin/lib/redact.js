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
 *  - Raw PII is NEVER persisted. Audit logs store type counts only.
 */

import { FIRST_NAMES, NAME_STOPWORDS, HONORIFICS } from "./gazetteer.js";
import { scoreMatch } from "./scoring.js";

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
    re: /[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}/gi,
  },
  CREDIT_CARD: {
    type: "CREDIT_CARD",
    re: /\b\d(?:[ \-]?\d){12,18}\b/g,
    validate: (m) => {
      const d = m.replace(/[ \-]/g, "");
      return d.length >= 13 && d.length <= 19 && luhnValid(d);
    },
  },
  SA_ID: {
    // South African 13-digit ID: YYMMDD prefix + Luhn. The date check keeps it
    // distinct from a 13-digit card so it classifies correctly (FutureFund market).
    type: "SA_ID",
    re: /\b\d{13}\b/g,
    validate: (m) => {
      if (!luhnValid(m)) return false;
      const mm = +m.slice(2, 4);
      const dd = +m.slice(4, 6);
      return mm >= 1 && mm <= 12 && dd >= 1 && dd <= 31;
    },
  },
  SSN: {
    type: "SSN",
    re: /\b\d{3}-\d{2}-\d{4}\b/g,
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
    re: /(?<!\w)(?:\+\d{1,3}[ \-.]?)?(?:\(\d{1,4}\)[ \-.]?|\d{1,4}[ \-.])?\d{2,6}(?:[ \-.]\d{2,6}){1,4}(?!\w)|(?<![\w.])\+\d{9,14}(?!\w)|(?<![\w.])\d{9,11}(?!\w)/g,
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
    re: /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g,
  },
  IBAN: {
    // Printed in 4-char groups (DE89 3704 0044 …) or contiguous (GB33BUKB…).
    type: "IBAN",
    re: /\b[A-Z]{2}\d{2}(?: [A-Z0-9]{4}){2,7}(?: [A-Z0-9]{1,4})?\b|\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b/g,
    validate: (m) => { const d = m.replace(/\s/g, ""); return d.length >= 15 && d.length <= 34; },
  },
  // ---- Extended identifier coverage (all high-precision / checksum- or format-gated) ----
  IPV6: {
    type: "IPV6",
    re: /\b(?:[A-F0-9]{1,4}:){2,7}[A-F0-9]{1,4}\b|\b(?:[A-F0-9]{1,4}:){1,7}:(?:[A-F0-9]{1,4}:?){0,6}[A-F0-9]{0,4}\b/gi,
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
    // 17 chars, no I/O/Q, mixes letters + digits (distinguishes from a hash/token).
    type: "VIN",
    re: /\b[A-HJ-NPR-Z0-9]{17}\b/gi,
    validate: (m) => /[A-HJ-NPR-Z]/i.test(m) && /\d/.test(m) && !/^\d+$/.test(m) && !/^[A-Z]+$/i.test(m),
  },
  PAN_INDIA: {
    // Indian Permanent Account Number: AAAAA1234A (5 letters, 4 digits, 1 letter).
    type: "PAN_INDIA",
    re: /\b[A-Z]{5}[0-9]{4}[A-Z]\b/g,
  },
  NINO_UK: {
    // UK National Insurance Number: two prefix letters (restricted set), 6 digits, a suffix A–D.
    type: "NINO_UK",
    re: /\b[ABCEGHJ-PRSTW-Z][ABCEGHJ-NPRSTW-Z] ?\d{2} ?\d{2} ?\d{2} ?[A-D]\b/g,
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
    re: /\b0x[a-fA-F0-9]{40}\b/g,
  },
  BTC_ADDRESS: {
    // Legacy (1/3…, base58) or bech32 (bc1…). Length-gated; base58 excludes 0/O/I/l.
    type: "BTC_ADDRESS",
    re: /\b(?:bc1[a-z0-9]{25,59}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b/g,
  },
  STREET_ADDRESS: {
    // Street number + name + a street-type suffix (Street/Ave/Rd/…). The suffix + a named
    // street between it and the number keep precision high (so "Section 3 Road map" won't hit).
    type: "STREET_ADDRESS",
    re: /\b\d{1,6}[A-Za-z]?\s+(?:[A-Z][A-Za-z'.\-]+\s+){1,4}(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct|Place|Pl|Way|Terrace|Ter|Close|Crescent|Cres|Square|Sq|Parkway|Pkwy|Highway|Hwy|Trail|Circle|Cir|Loop|Row|Walk)\b\.?/g,
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
  VIN:            { level: "medium", score: 0.75, reason: "17-character VIN structure (letters + digits, no I/O/Q)" },
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
const TYPE_PRECEDENCE = {
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
export function detectPersons(text, mode = "balanced") {
  const guessFromHonorific = mode !== "strict"; // strict will not infer a name it does not know
  const spans = [];
  // 1-3 Title-Case words. High precision: a bare Title-Case phrase is NOT enough (documents
  // are full of Title-Case headings/terms). We keep a span only with a real name signal:
  //   • a known first name followed by a Capitalised surname ("John Smith", "Thabo Mbeki"), or
  //   • an honorific, either in the span ("Mr Smith") or right before it ("Dr" "Jane Doe").
  const re = /\b[A-Z][a-z'’.\-]*[a-z'’](?:[ \t]+[A-Z][a-z'’.\-]*[a-z'’]){0,2}\b/g;
  let m;
  while ((m = re.exec(text)) !== null) {
    const value = m[0];
    const start = m.index;
    const tokens = value.split(/\s+/);
    const lower = tokens.map((t) => t.toLowerCase().replace(/[.'’-]+$/, ""));
    if (lower.every((t) => NAME_STOPWORDS.has(t))) continue;

    let keep = false, s = start, v = value, viaHonorific = false;

    // Honorific as the first token: "Mr Smith", "Dr Jane Doe" → the run after the title.
    if (HONORIFICS.has(lower[0]) && tokens.length >= 2) {
      const rel = value.indexOf(tokens[1]);
      keep = true; viaHonorific = true; s = start + rel; v = value.slice(rel);
    } else {
      // Honorific immediately before the span: "Dr" then "Jane Doe".
      const pre = text.slice(Math.max(0, start - 14), start);
      const honBefore = /\b([A-Za-z]{2,12})\.?\s+$/.exec(pre);
      const knownIdx = lower.findIndex((t) => FIRST_NAMES.has(t));
      if (honBefore && HONORIFICS.has(honBefore[1].toLowerCase())) {
        keep = true; viaHonorific = true;
      } else if (knownIdx >= 0 && knownIdx < tokens.length - 1) {
        // Known first name with a following surname → keep from the first name onward.
        const rel = value.indexOf(tokens[knownIdx]);
        keep = true; if (rel > 0) { s = start + rel; v = value.slice(rel); }
      }
      // A lone known first name ("John"), surname-first order, or a bare Title-Case phrase
      // (e.g. the place name "Port Louis") → NOT kept: too noisy without a leading given name.
    }

    // STRICT: the honorific alone is a guess, and strict does not guess. "Dr Sarah Johnson"
    // survives because Sarah is in the gazetteer; "Mr Naledi Khumalo" does not, because the only
    // thing telling us Naledi is a person is the "Mr".
    if (keep && viaHonorific && !guessFromHonorific) {
      const kept = v.split(/\s+/).map((t) => t.toLowerCase().replace(/[.'’-]+$/, ""));
      if (!kept.some((t) => FIRST_NAMES.has(t))) keep = false;
    }

    if (keep) {
      // Trim a trailing stopword the pattern swallowed ("Jane Doe Please" → "Jane Doe").
      let vt = v.split(/\s+/);
      while (vt.length > 1 && NAME_STOPWORDS.has(vt[vt.length - 1].toLowerCase().replace(/[.'’-]+$/, "")) && !FIRST_NAMES.has(vt[vt.length - 1].toLowerCase())) {
        v = v.slice(0, v.lastIndexOf(vt[vt.length - 1])).replace(/\s+$/, ""); vt = v.split(/\s+/);
      }
      // How it was proven: an honorific-only guess is weaker evidence than a known first name, and
      // the scorer must be able to tell them apart. If the kept value contains a gazetteer name,
      // that is the stronger signal even when an honorific was also present.
      if (v) {
        const gaz = v.split(/\s+/).some((t) => FIRST_NAMES.has(t.toLowerCase().replace(/[.'’-]+$/, "")));
        spans.push({ start: s, end: s + v.length, type: "PERSON", value: v, via: gaz ? "gazetteer" : "honorific" });
      }
    }
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
const LABEL_NAME = /\b(?:full name|first name|last name|sur\s?name|name|patient|beneficiary|cardholder|account holder)\s*[:=]\s*([A-Za-z][A-Za-z'’\-]+(?:[ \t]+[A-Za-z][A-Za-z'’\-]+){0,2})|\b(?:full name|first name|last name|sur\s?name|name|patient|beneficiary|cardholder|account holder)[ \t]+([A-Za-z][A-Za-z'’\-]+(?:[ \t]+[A-Za-z][A-Za-z'’\-]+){0,2})/gi;
// Personal identifier labels only. Generic transactional/document labels (reference, order,
// invoice, file, record, case, folio) are deliberately excluded — in business documents they
// tag non-personal numbers and caused over-masking.
const LABEL_ID = /\b(?:medical aid|health plan|scheme|policy|membership|account|acc|passport|licen[cs]e|employee|staff|customer|tax|vat|national id|id|patient)\s*(?:numbers?|no\.?|nr|#|id)?\s*[:=#]?\s+([A-Za-z0-9][A-Za-z0-9\-/]{3,})/gi;
// Date of birth: a DOB label + a date value (numeric or "1 January 1990"). We mask the DATE
// only when it's a birth date — plain dates elsewhere stay (they're not personal on their own).
const LABEL_DOB = /\b(?:date of birth|d\.?\s?o\.?\s?b\.?|birth\s?date|date born|born(?:\s+on)?)\s*[:=]?\s+((?:\d{1,4}[-/.]\d{1,2}[-/.]\d{1,4})|(?:\d{1,2}(?:st|nd|rd|th)?\s+[A-Za-z]{3,9},?\s+\d{4})|(?:[A-Za-z]{3,9}\s+\d{1,2}(?:st|nd|rd|th)?,?\s+\d{4}))/gi;
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
  while (keep > 1 && NAME_STOPWORDS.has(norm(toks[keep - 1])) && !FIRST_NAMES.has(norm(toks[keep - 1]))) keep--;
  const kept = toks.slice(0, keep);
  if (!kept.length) return null;
  if (NAME_STOPWORDS.has(norm(kept[0]))) return null;         // "of the file", "not provided"
  const titleCase = kept.every((t) => /^[A-Z]/.test(t));
  const known = kept.some((t) => FIRST_NAMES.has(norm(t)));
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
    PERSON: false, // heuristic — off by default; clients opt in
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

export class RedactionSession {
  constructor(config = DEFAULT_CONFIG) {
    this.config = { ...DEFAULT_CONFIG, ...config };
    this.counters = {}; // type -> running counter
    this.byKey = new Map(); // `${type}::${norm}` -> token
    this.tokenToOriginal = new Map(); // token -> original value
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
      if (this.config.detectors?.[type]) out.push(det);
    }
    for (const p of this.config.customPatterns || []) {
      const source = p.pattern || p.regex; // accept either field name
      if (!source) continue;
      const flags = (p.flags || "").includes("g") ? p.flags : (p.flags || "") + "g"; // always global for matchAll
      try {
        out.push({ type: p.type || p.name || "CUSTOM", re: new RegExp(source, flags), via: "custom" });
      } catch {
        /* skip invalid user regex */
      }
    }
    return out;
  }

  _customTermMatches(text) {
    const terms = (this.config.customTerms || []).filter(Boolean);
    if (!terms.length) return [];
    const escaped = terms
      .slice()
      .sort((a, b) => b.length - a.length)
      .map((t) => t.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"));
    const re = new RegExp(`(?<![\\w])(?:${escaped.join("|")})(?![\\w])`, "gi");
    const matches = [];
    for (const m of text.matchAll(re)) {
      matches.push({ start: m.index, end: m.index + m[0].length, type: "CUSTOM", value: m[0], via: "term" });
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
    this.counts[type] = (this.counts[type] || 0) + 1;
    this.total += 1;
    return token;
  }

  /** Redact a single string, returning the masked text. */
  /** Detected, overlap-resolved, non-overlapping matches [{start,end,type,value}], sorted. */
  _chosen(text) {
    let matches = [];
    for (const det of this._activeDetectors()) {
      det.re.lastIndex = 0;
      for (const m of text.matchAll(det.re)) {
        const value = m[0];
        if (det.validate && !det.validate(value)) continue;
        const via = det.via || VIA_BY_TYPE[det.type] || "shape";
        matches.push({ start: m.index, end: m.index + value.length, type: det.type, value, via });
      }
    }
    matches = matches.concat(this._customTermMatches(text));
    matches = matches.concat(detectLabeled(text)); // always on — labelled PII auto-pickup
    if (this.config.detectors?.PERSON) {
      matches = matches.concat(detectPersons(text, this.config.personMode || "balanced"));
    }
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
      const seen = {};
      for (const m of matches) seen[m.type] = (seen[m.type] || 0) + 1;
      matches = matches.filter((m) => (seen[m.type] || 0) >= (this.instanceThreshold[m.type] || 1));
    }
    if (!matches.length) return [];
    // Resolve overlaps: sort by start, then by precedence, then by length.
    matches.sort((a, b) => {
      if (a.start !== b.start) return a.start - b.start;
      const pa = TYPE_PRECEDENCE[a.type] || 0;
      const pb = TYPE_PRECEDENCE[b.type] || 0;
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
      out += token;
      cursor = m.end;
    }
    out += text.slice(cursor);
    return out;
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
      spans.push({ start: m.start, end: m.end, token, original: m.value, type: m.type, id: m.id, level: m.level, confidence: m.confidence, reason: m.reason });
      out += token;
      cursor = m.end;
    }
    out += text.slice(cursor);
    return { redacted: out, spans };
  }

  /** Replace tokens with the original values (used on the response path). */
  rehydrate(text) {
    if (typeof text !== "string" || text.length === 0 || this.tokenToOriginal.size === 0) return text;
    let out = text;
    for (const [token, original] of this.tokenToOriginal) {
      if (out.includes(token)) out = out.split(token).join(original);
    }
    return out;
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
