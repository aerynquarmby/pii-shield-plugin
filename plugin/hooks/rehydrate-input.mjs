#!/usr/bin/env node
/**
 * PreToolUse — put the real values back before content lands on disk.
 *
 * The outbound half. Because Claude only ever saw [EMAIL_1], anything it writes carries
 * the token, not the address. Without this hook the tokens get committed into the user's
 * source tree. With it, Write/Edit receive the original values and the wire never does.
 *
 * Deliberately does NOT emit `permissionDecision`. Returning "allow" here would silently
 * auto-approve every write in the session — a redaction plugin has no business widening
 * the permission model. `updatedInput` is emitted alone; verified to take effect.
 *
 * KNOWN LIMITATION — Edit/MultiEdit `old_string`. We rehydrate `old_string` too, and the
 * updated value is correct, but Claude Code matches `old_string` against the file BEFORE the
 * rehydrated input is applied. Claude saw the redacted token; the file holds the real value;
 * the match therefore fails with "String to replace not found". This is a host ordering issue
 * we cannot fix from a hook — the fix has to come from Claude Code applying updatedInput before
 * the match. Until then, editing a line that contains detected PII must go through Write (whole
 * file), whose content IS rehydrated before it lands, rather than a targeted Edit.
 */
import fs from "node:fs";
import { load } from "../lib/session-store.mjs";
import { mapStrings, unchanged } from "../lib/walk.mjs";

let input = {};
try {
  input = JSON.parse(fs.readFileSync(0, "utf8"));
} catch {
  process.exit(0);
}

const original = input.tool_input;
if (!original || typeof original !== "object") process.exit(0);

try {
  const session = load(input.session_id);
  // Nothing was ever masked in this session, so nothing can need restoring.
  if (session.tokenToOriginal.size === 0) process.exit(0);

  const restored = mapStrings(original, (s) => session.rehydrate(s));
  if (unchanged(original, restored)) process.exit(0);

  process.stdout.write(JSON.stringify({
    hookSpecificOutput: { hookEventName: "PreToolUse", updatedInput: restored },
  }));
} catch (err) {
  // Fail open, but loudly. A failed rehydrate writes a token into a file: ugly and
  // obvious, and the user can fix it. Blocking the write would lose their work.
  process.stderr.write(`pii-shield: rehydrate failed, tokens may be written literally: ${err?.message ?? err}\n`);
}
process.exit(0);
