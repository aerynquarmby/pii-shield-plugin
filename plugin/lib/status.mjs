#!/usr/bin/env node
/**
 * Print the workspace's PII Shield plan status — so you can see your limits the way Claude
 * shows its own: monthly allowance used/left, plus any pay-as-you-go credits in reserve, and
 * how much redaction headroom remains before protection pauses. Invoked by the /pii-shield:status
 * slash command and runnable directly:  node lib/status.mjs
 */
import { resolveGate, readKey } from "./gate.mjs";

const API = (process.env.PII_SHIELD_API || "https://piishield.ai").replace(/\/$/, "");
const n = (x) => Number(x || 0).toLocaleString();

/** Pure formatter — takes the gate result and returns the multi-line report. Unit-tested. */
export function formatStatus(g, { hasKey, api } = { hasKey: true, api: API }) {
  // The key lives in the dashboard, under Integration. Signup alone no longer yields one: the
  // address has to be confirmed first, so pointing a keyless user only at /signup is a dead end
  // if they already have an account.
  if (!hasKey) return "PII Shield: no workspace key set.\n  Set PII_SHIELD_KEY, or write it to ~/.pii-shield/key.\n  Your key is in your dashboard under Integration: " + api + "/my\n  No account yet? " + api + "/signup (confirm your email, then the key is in the dashboard).";
  if (g.reason === "invalid_key") return "PII Shield: that workspace key is not valid. Check it, or get a new one at " + api + "/my";
  if (g.reason === "unreachable") return "PII Shield: couldn't reach the server to check your plan right now (offline). Protection uses your last confirmed status.";

  const plan = g.plan || "trial";
  const planName = plan[0].toUpperCase() + plan.slice(1);
  const unlimited = g.limit === -1;
  const used = g.used ?? 0;
  const limit = g.limit;
  const credits = g.credits ?? 0;
  const monthlyLeft = unlimited ? Infinity : (g.remaining ?? Math.max(0, limit - used));

  const lines = [`PII Shield - ${planName} plan${g.stale ? " (last confirmed offline)" : ""}`];

  if (unlimited) {
    lines.push("  This month:    unlimited (no cap)");
  } else {
    const pct = limit ? Math.round((used / limit) * 100) : 0;
    lines.push(`  This month:    ${n(used)} / ${n(limit)} used  (${n(monthlyLeft)} left, ${pct}%)`);
  }

  if (credits > 0) {
    lines.push(`  Pay-as-you-go: ${n(credits)} credits in reserve`);
    if (!unlimited && monthlyLeft === 0) lines.push("                 monthly allowance is spent; now drawing on credits");
  } else {
    lines.push("  Pay-as-you-go: none");
  }

  if (!unlimited) lines.push(`  Headroom:      ${n(monthlyLeft + credits)} redactions before protection pauses`);

  if (g.open) {
    lines.push("  Status:        ✓ active. PII is being redacted.");
    const left = monthlyLeft + credits;
    if (!unlimited && left > 0 && left <= 25) {
      lines.push(`  ⚠ Low: only ${n(left)} left. Top up at ${api}/my (Billing) so protection doesn't pause.`);
    }
  } else {
    lines.push("  Status:        ✕ paused. Monthly allowance and credits are exhausted.");
    lines.push(`                 Prompts and tool output containing PII are withheld until you top up: ${api}/my`);
  }

  // The status says "active". It must also say what active does NOT mean, or "active" reads as
  // "safe". Same sentence as every other surface.
  lines.push("");
  lines.push("  Detection is automated and is not a guarantee. It can miss personal data.");
  lines.push("  Always review what you send to an AI. You use it at your own risk.");

  return lines.join("\n");
}

// Run as a script (not when imported by a test).
if (import.meta.url === `file://${process.argv[1]}`) {
  const g = readKey() ? await resolveGate() : {};
  console.log(formatStatus(g, { hasKey: !!readKey(), api: API }));
}
