#!/usr/bin/env node
/**
 * UserPromptSubmit — the only place PII can be stopped before *you* send it.
 *
 * Claude Code does not let a hook rewrite a prompt (`updatedPrompt` is silently ignored;
 * measured, not assumed). So this hook cannot redact. It can only detect and block.
 *
 * It covers two paths the tool hooks cannot see at all:
 *   - what you typed or pasted
 *   - @-mentioned files, whose contents are expanded into a separate message AFTER every
 *     hook has run. No PostToolUse fires for them. Blocking here is the only defence.
 *
 * PII_SHIELD_PROMPT_MODE = block (default) | warn | off
 */
import fs from "node:fs";
import path from "node:path";
import { RedactionSession } from "../lib/redact.js";
import { configFromEnv } from "../lib/session-store.mjs";
import { resolveGate, blockedMessage } from "../lib/gate.mjs";

const MODE = process.env.PII_SHIELD_PROMPT_MODE || "block";
if (MODE === "off") process.exit(0);

const MAX_MENTION_BYTES = 2 * 1024 * 1024;

let input = {};
try {
  input = JSON.parse(fs.readFileSync(0, "utf8"));
} catch {
  process.exit(0);
}

const prompt = typeof input.prompt === "string" ? input.prompt : "";
const cwd = input.cwd || process.cwd();

// Only act on detections at least this confident. Lets a team stop being interrupted by
// heuristic hits (names, addresses) while still hard-blocking checksum-proven cards/IDs.
//   PII_SHIELD_MIN_CONFIDENCE = high | medium   (default: everything)
const MIN_CONF = process.env.PII_SHIELD_MIN_CONFIDENCE || "";

/** Detect without consuming tokens from the real session: throwaway session, never saved. */
function detectIn(text) {
  const cfg = configFromEnv();
  const probe = new RedactionSession(MIN_CONF ? { ...cfg, minConfidenceLevel: MIN_CONF } : cfg);
  probe.scan(text); // dry run — never rewrites
  return probe.findingList();
}

const findings = [];

const inPrompt = detectIn(prompt);
if (inPrompt.length) findings.push({ where: "your prompt", items: inPrompt });

// @-mentions: Claude Code inlines these into a separate user message after hooks run.
for (const m of prompt.matchAll(/(?:^|\s)@([^\s]+)/g)) {
  const rel = m[1].replace(/[.,;:)\]]+$/, "");
  const abs = path.resolve(cwd, rel);
  try {
    const st = fs.statSync(abs);
    if (!st.isFile() || st.size > MAX_MENTION_BYTES) continue;
    const items = detectIn(fs.readFileSync(abs, "utf8"));
    if (items.length) findings.push({ where: `@${rel}`, items });
  } catch { /* not a readable path — Claude Code will handle the mention itself */ }
}

if (!findings.length) process.exit(0);

// A reasoning trace, not a bare type list: what was found, how sure we are, and why — so you
// can judge a heuristic name hit differently from a Luhn-valid card. Values are NEVER printed.
const summary = findings.map((f) =>
  `  • ${f.where}\n` + f.items.map((i) => `      - ${i.type} (${i.level}, ${i.count}×) — ${i.reason}`).join("\n")
).join("\n");

// A shut gate (no key, invalid key, over limit) blocks regardless of PII_SHIELD_PROMPT_MODE.
// Turning the prompt guard to `warn` must not be a way to keep using the product unpaid.
const gate = await resolveGate();
if (!gate.open) {
  process.stdout.write(JSON.stringify({
    decision: "block",
    reason: `${blockedMessage(gate, "This prompt")}\n\nDetected in:\n${summary}`,
  }));
  process.exit(0);
}

if (MODE === "warn") {
  process.stdout.write(JSON.stringify({
    hookSpecificOutput: {
      hookEventName: "UserPromptSubmit",
      additionalContext:
        `PII Shield detected personal data in this prompt and did not mask it ` +
        `(prompts cannot be rewritten by a hook):\n${summary}\n` +
        `Do not echo these values back.`,
    },
  }));
  process.exit(0);
}

// block: the prompt is discarded, not sent. This is the only guarantee available here.
process.stdout.write(JSON.stringify({
  decision: "block",
  reason:
    `PII Shield blocked this prompt — it contains personal data that a hook cannot mask ` +
    `before it reaches the model:\n${summary}\n\n` +
    `Claude Code does not allow prompts or @-mentions to be redacted in place, only blocked. ` +
    `Rewrite the prompt without the personal data, or let Claude read the file with the Read ` +
    `tool instead of @-mentioning it — tool output IS redacted automatically.\n` +
    `Set PII_SHIELD_PROMPT_MODE=warn to allow with a warning, or =off to disable.`,
}));
process.exit(0);
