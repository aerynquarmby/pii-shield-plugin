#!/usr/bin/env node
/**
 * PostToolUse — redact PII out of a tool result before it enters the model's context,
 * and meter it against the workspace plan exactly like the browser extension.
 *
 * Order of operations matters:
 *   1. Detect locally. No PII -> emit nothing, touch the network never. (The common case.)
 *   2. PII found -> resolve the billing gate (cached; at most one call a minute).
 *   3. Gate open  -> redact, report COUNTS ONLY, emit the redacted output.
 *      Gate shut  -> WITHHOLD the output and tell the user why.
 *
 * Step 3's shut branch is the important one. "Stop redacting when out of quota" cannot mean
 * "pass the raw file through to the model" — that would turn a billing event into a data
 * breach. Over-limit means the content does not travel at all, which is also what the
 * extension does: it blocks the send.
 *
 * Two hard-won details (see tools/canary/FINDINGS.md):
 *   - the payload key is `tool_response`, not the documented `tool_output`
 *   - `updatedToolOutput` must keep the ORIGINAL TYPE. A string where an object was
 *     expected is silently dropped and the raw output reaches the API.
 */
import fs from "node:fs";
import { RedactionSession } from "../lib/redact.js";
import { load, save, configFromEnv, configFromGate } from "../lib/session-store.mjs";
import { mapStrings, unchanged } from "../lib/walk.mjs";
import { resolveGate, meterUsage, reportLeaks, blockedMessage } from "../lib/gate.mjs";
import { maskPreview } from "../lib/field-cipher.js";

const PREVIEW = process.env.PII_SHIELD_LEAK_PREVIEW !== "0";
const typeOf = (token) => (token.match(/\[([A-Z][A-Z0-9_]*)_\d+\]/) || [])[1] || "PII";

const FAILSAFE = "[pii-shield: redaction failed — output withheld]";

let input = {};
try {
  input = JSON.parse(fs.readFileSync(0, "utf8"));
} catch {
  process.exit(0);
}

const original = input.tool_response ?? input.tool_output;
if (original === undefined) process.exit(0);

const emit = (updated) => {
  process.stdout.write(JSON.stringify({
    hookSpecificOutput: { hookEventName: "PostToolUse", updatedToolOutput: updated },
  }));
  process.exit(0);
};

/** Withhold every string leaf, preserving shape so the replacement is actually accepted. */
const withhold = (notice) => emit(mapStrings(original, () => notice));

try {
  // 1. Local detection first — a throwaway session, so no tokens are consumed if we end up
  //    withholding. Nothing here touches the network.
  const probe = new RedactionSession(configFromEnv());
  mapStrings(original, (s) => probe.redactText(s));
  if (probe.total === 0) process.exit(0); // no PII: fast path, stay silent and offline

  // 2. There is PII. Now, and only now, does the plan matter.
  const gate = await resolveGate();
  if (!gate.open) withhold(blockedMessage(gate, "This tool output"));

  // 3. Redact for real, against the session's stable token map and the workspace's rules.
  //    Workspace `allowTerms` (values an admin marked "Not PII") arrive with the gate config,
  //    so suppressed values are never masked here and never reach the audit either.
  const session = load(input.session_id, configFromGate(gate));
  const before = session.total;
  const seen = new Set(session.tokenToOriginal.keys());
  const redacted = mapStrings(original, (s) => session.redactText(s));
  if (unchanged(original, redacted)) process.exit(0);
  if (session.total !== before) save(input.session_id, session);

  // Counts only. Never a value, never the text. `probe` holds this call's own tallies;
  // `session.counts` is cumulative for the whole session and would over-report.
  const overLimit = await meterUsage(probe.total, probe.counts, "plugin");
  if (overLimit) withhold(blockedMessage({ reason: "over_limit", plan: gate.plan }, "This tool output"));

  // Leak Audit: one row per value first masked on this call. Previews are computed here;
  // the value itself never leaves the machine.
  // The preview is computed here and encrypted to the workspace's public key inside
  // reportLeaks(). The raw value, and the plaintext preview, never leave this machine.
  const events = [];
  for (const [token, value] of session.tokenToOriginal) {
    if (seen.has(token)) continue;
    const type = typeOf(token);
    events.push({ type, value, preview: PREVIEW ? maskPreview(value, type) : "", convo_ref: `cli:${input.session_id}` });
  }
  await reportLeaks(events, gate);

  emit(redacted);
} catch (err) {
  // Fail closed. A crashing redactor must never hand raw content to the model.
  process.stderr.write(`pii-shield: ${err?.message ?? err}\n`);
  withhold(FAILSAFE);
}
