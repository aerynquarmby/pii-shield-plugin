/**
 * Evidence-based confidence.
 *
 * The old model scored by TYPE: every PERSON was 0.70, every PHONE 0.75, forever. So "John Smith",
 * anchored by a known first name, and "behind it", scraped out of "the name behind it", carried the
 * identical score — and the Leak Audit dutifully recorded the second one at medium confidence. A
 * score that says the same thing about every match of a type carries no information: you cannot
 * triage by it, and you cannot threshold on it.
 *
 * So score the MATCH, not the type, from three kinds of evidence:
 *
 *   1. HOW it was found. A Luhn-checked card is not the same claim as a ten-digit run that merely
 *      looks like a phone number. A name anchored by the gazetteer is not the same claim as one
 *      inferred from a "Mr".
 *
 *   2. What sits AROUND it. "card ending 4111…" and a bare "4111…" are different amounts of
 *      evidence for the same digits. This is Presidio's context enhancer and Google DLP's hotword
 *      rules, and it is the single highest-value signal available without an ML model.
 *
 *   3. What sits around it that ARGUES AGAINST it. "order 0821234567" is an order number. The
 *      digits are identical to a phone number; only the preceding word says otherwise. Google DLP
 *      calls these exclusion rules. Without them a DLP tool drowns its user in transactional refs,
 *      which is exactly how a security product trains people to ignore it.
 *
 * A finding whose evidence does not clear FLOOR is not reported at all. Everything else carries a
 * score a human can sort by and a reason that says what the evidence actually was.
 */

/** How a match was found. The base score is a claim about the strength of that method alone. */
export const BASE = {
  term: 0.99,       // one of the workspace's own always-mask terms. Not a guess.
  custom: 0.96,     // the workspace's own regex. They asked for exactly this.
  checksum: 0.95,   // Luhn / Verhoeff / mod-97 / date validity actually passed.
  structural: 0.90, // a format too rigid to hit by accident (email, IBAN, MAC, 0x-address).
  gazetteer: 0.80,  // a known given name followed by a surname.
  label: 0.78,      // a value sitting next to a personal-identifier label.
  honorific: 0.62,  // a title, and a name we do not know. A reasonable guess, and only a guess.
  shape: 0.55,      // it merely looks right. A phone shape, a VIN shape, a street shape.
};

// Words that, near a match, support it. Proximity matters more than presence: "card" three words
// away is evidence; "card" three paragraphs away is coincidence.
const HOTWORDS = {
  CREDIT_CARD: ["card", "credit", "debit", "visa", "mastercard", "amex", "cvv", "cvc", "expiry", "expires", "ending", "payment", "pay", "pan", "cardholder"],
  PHONE: ["phone", "tel", "telephone", "mobile", "cell", "cellphone", "call", "whatsapp", "fax", "contact", "reach", "ring", "dial"],
  EMAIL: ["email", "e-mail", "mail", "contact", "reach", "address", "cc", "bcc"],
  SA_ID: ["id", "identity", "identification", "national"],
  SSN: ["ssn", "social", "security"],
  IBAN: ["iban", "bank", "account", "swift", "bic", "transfer", "payment"],
  PASSPORT: ["passport"],
  DOB: ["birth", "born", "dob", "birthday"],
  ID: ["number", "no", "nr", "reference", "member", "policy", "account"],
  PERSON: ["mr", "mrs", "ms", "miss", "dr", "prof", "sir", "name", "contact", "signed", "prepared", "reviewed", "approved", "attn", "regards", "sincerely", "dear", "spoke", "met", "called"],
  STREET_ADDRESS: ["address", "street", "road", "avenue", "lives", "resides", "deliver", "postal"],
  VIN: ["vin", "vehicle", "chassis", "registration"],
};

/**
 * Words that argue AGAINST a numeric match. A ten-digit run after "order" is an order number, and
 * a sixteen-digit run after "invoice" is an invoice reference that happens to satisfy Luhn.
 *
 * These fire only when the word IMMEDIATELY precedes the value, because that is the only position
 * where they are actually labelling it. "the invoice was paid, call 0821234567" must stay a phone.
 */
const ANTIWORDS = [
  "order", "invoice", "ref", "reference", "ticket", "case", "sku", "batch", "serial", "tracking",
  "receipt", "quote", "po", "purchase", "item", "product", "part", "model", "build", "version",
  "row", "line", "record", "job", "task", "issue", "bug", "pr", "commit", "port", "pid", "seed",
];

/** Types whose value is only digits/shape, and which an anti-word can therefore rescue us from. */
const NUMERIC_TYPES = new Set(["PHONE", "CREDIT_CARD", "SA_ID", "SSN", "ID", "VIN", "IPV4"]);

const CONTEXT_WINDOW = 42;   // characters either side. About seven words.
const IMMEDIATE_BEFORE = 16; // an anti-word must be labelling the value, not merely nearby.

export const FLOOR = 0.35;   // below this, the evidence does not support reporting it at all.
const HIGH = 0.85;
const MEDIUM = 0.60;

const levelFor = (s) => (s >= HIGH ? "high" : s >= MEDIUM ? "medium" : "low");
const words = (s) => (s.toLowerCase().match(/[a-z][a-z'-]*/g) || []);

/**
 * Score one match from its own evidence.
 *
 * `m` is { type, value, start, end, via }. `text` is the surrounding document.
 * Returns { confidence, level, reason } — or null when the evidence does not clear the floor, in
 * which case the caller must drop the finding entirely rather than report a weak one.
 */
export function scoreMatch(m, text) {
  const via = m.via || "shape";
  let score = BASE[via] ?? BASE.shape;
  const why = [];

  switch (via) {
    case "checksum": why.push(checksumReason(m.type)); break;
    case "structural": why.push(structuralReason(m.type)); break;
    case "gazetteer": why.push("Known first name followed by a capitalised surname"); break;
    case "honorific": why.push("Introduced by a title, but the given name is not one we know"); break;
    case "label": why.push("Value sitting next to a personal-identifier label"); break;
    case "term": why.push("One of your always-mask terms"); break;
    case "custom": why.push(`Matched your custom "${m.type}" pattern`); break;
    default: why.push(shapeReason(m.type));
  }

  const before = text.slice(Math.max(0, m.start - CONTEXT_WINDOW), m.start);
  const after = text.slice(m.end, m.end + CONTEXT_WINDOW);

  // 1. Supporting context. Only worth something for types that can be confused with a non-PII value;
  //    an email needs no help from the word "email" to be an email.
  const hot = HOTWORDS[m.type] || [];
  if (hot.length) {
    const near = new Set([...words(before), ...words(after)]);
    const hit = hot.find((w) => near.has(w));
    if (hit) {
      score += 0.15;
      why.push(`"${hit}" appears next to it`);
    }
  }

  // 2. Context that argues against it. Only immediately before, where it is actually labelling the
  //    value: "order 0821234567" is an order number; "call 0821234567 about the order" is a phone.
  if (NUMERIC_TYPES.has(m.type)) {
    const tail = words(text.slice(Math.max(0, m.start - IMMEDIATE_BEFORE), m.start));
    const last = tail[tail.length - 1];
    if (last && ANTIWORDS.includes(last)) {
      score -= 0.45;
      why.push(`but "${last}" immediately precedes it, which usually labels a transactional number`);
    }
  }

  // 3. A person whose name is entirely lowercase is prose until proven otherwise. This is the exact
  //    shape of "behind it" — and of every other phrase a label scraper drags in.
  if (m.type === "PERSON" && via !== "term" && m.value === m.value.toLowerCase()) {
    score -= 0.2;
    why.push("but the name is not capitalised");
  }

  score = Math.max(0, Math.min(0.99, score));
  if (score < FLOOR) return null;

  return { confidence: Number(score.toFixed(2)), level: levelFor(score), reason: capitalise(why.join(", ")) };
}

const capitalise = (s) => (s ? s[0].toUpperCase() + s.slice(1) : s);

function checksumReason(type) {
  return {
    CREDIT_CARD: "Luhn-valid card number",
    SA_ID: "Luhn-valid 13-digit South African ID with a valid date",
    AADHAAR: "Verhoeff-checked Aadhaar number",
    IBAN: "IBAN country code and check digits",
    NINO_UK: "UK National Insurance number with a valid prefix",
    DOB: "A date next to a date-of-birth label",
  }[type] || `${type} passed its checksum`;
}
function structuralReason(type) {
  return {
    EMAIL: "Email address structure",
    IPV6: "IPv6 address",
    MAC: "MAC address",
    ETH_ADDRESS: "Ethereum address (0x and 40 hex characters)",
    BTC_ADDRESS: "Bitcoin address structure",
    PAN_INDIA: "Indian PAN structure (AAAAA1234A)",
  }[type] || `${type} structure`;
}
function shapeReason(type) {
  return {
    PHONE: "Digits shaped like a phone number",
    VIN: "17 characters shaped like a VIN",
    STREET_ADDRESS: "A number followed by a named street and a street type",
    IPV4: "Four dotted integers",
    SSN: "US Social Security number format",
    ID: "Value next to a personal-identifier label",
  }[type] || `${type} pattern`;
}
