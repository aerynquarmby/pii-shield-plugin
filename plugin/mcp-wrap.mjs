#!/usr/bin/env node
/**
 * PII Shield MCP wrapper — put the shield in front of an MCP server you do not control.
 *
 *     Claude  <──stdio──>  [ this wrapper ]  <──stdio──>  Greenhouse / Workday / any MCP server
 *
 * The problem this solves. An ATS vendor's MCP server hands a model whole candidate records:
 * names, emails, phone numbers, ID numbers, CV attachments. Asking the vendor to integrate
 * redaction means a roadmap conversation with someone else's engineering team, and asking the model
 * to redact after the fact is theatre — it already has the data, the data is already in the
 * conversation, and that conversation may later be shared or indexed.
 *
 * So intercept the transport instead. Nobody's server changes, nobody ships an integration, and the
 * model never receives a raw record.
 *
 * DIRECTION IS THE WHOLE DESIGN. Two flows, opposite treatments:
 *
 *   tool RESULT   upstream ──▶ model     REDACT.  This is the pre-redaction that matters: the
 *                                        record is tokenised before the model, the transcript or
 *                                        any later share ever sees it.
 *
 *   tool ARGS     model ──▶ upstream     REHYDRATE. The model only ever knew [EMAIL_1], so when it
 *                                        calls back with `{"email":"[EMAIL_1]"}` the real address
 *                                        has to be restored or the ATS lookup fails. This is what
 *                                        makes an agent able to actually work: it can act on a
 *                                        person it was never shown.
 *
 * One session for the process, so the same candidate carries the same token across every call.
 * `[EMAIL_2] applied twice` is a sentence about one person; per-call tokens would destroy that.
 *
 * IT FAILS CLOSED. No key, an invalid key, an unreachable shield or an exhausted plan and a tool
 * call returns an error — never the unredacted result. A wrapper that quietly stops redacting is
 * worse than one that visibly breaks, because nobody finds out.
 *
 * Tool names and JSON schemas are never touched: they are the contract the agent calls against, and
 * rewriting one breaks it. Their free-text DESCRIPTIONS are scanned, because a hand-written server
 * has no personal data in a description and a server that mints one tool per candidate has the
 * candidate's name in every one — and that reaches the model before a single tool is called.
 *
 * Usage — a server that runs LOCALLY (stdio). Wrap it directly:
 *   PII_SHIELD_KEY=shield_… node mcp-wrap.mjs -- npx -y @modelcontextprotocol/server-filesystem ~/cvs
 *
 * Usage — a REMOTE server (an https:// endpoint, which is what most hosted ATS MCPs are, Greenhouse
 * included). There is no process to spawn, so bridge it to stdio first and wrap the bridge:
 *   PII_SHIELD_KEY=shield_… node mcp-wrap.mjs -- npx -y mcp-remote https://your-ats.example.com/mcp
 *
 * Take the URL from your vendor's own documentation. mcp-remote handles the OAuth for you.
 *
 * Claude Desktop / Claude Code
 *   { "mcpServers": { "ats": {
 *       "command": "node",
 *       "args": ["/path/to/mcp-wrap.mjs", "--", "npx", "-y", "mcp-remote", "https://your-ats.example.com/mcp"],
 *       "env": { "PII_SHIELD_KEY": "shield_…" } } } }
 *
 * Everything after `--` is the upstream server's own command line, run as a child process with the
 * environment it was given. Its stderr is forwarded untouched so its diagnostics still reach you.
 *
 * NOTE: pointing your client at a remote ATS URL *directly* connects it with no shield in the path.
 * The wrapper has to be the thing your client launches, or it is not involved at all. Handing this
 * wrapper a bare URL exits with an error rather than pretending to work.
 *
 * Zero dependencies beyond the redaction engine beside this file.
 */
import { spawn } from "node:child_process";
import { RedactionSession, DEFAULT_CONFIG } from "./lib/redact.js";

let OVER_LIMIT = false;   // set from startup config, then kept current by the metering reply
const ORIGIN = process.env.PII_SHIELD_ORIGIN || "https://piishield.ai";
const KEY = (process.env.PII_SHIELD_KEY || "").trim();
const DEBUG = process.env.PII_SHIELD_DEBUG === "1";

const log = (...a) => process.stderr.write("[pii-shield] " + a.join(" ") + "\n");
const debug = (...a) => { if (DEBUG) log(...a); };

// ── the upstream command ───────────────────────────────────────────────────────────────────────
const dashdash = process.argv.indexOf("--");
const upstreamArgv = dashdash >= 0 ? process.argv.slice(dashdash + 1) : [];
if (!upstreamArgv.length) {
  log("nothing to wrap. Usage: PII_SHIELD_KEY=shield_… node mcp-wrap.mjs -- <server command…>");
  process.exit(2);
}
if (!KEY) {
  // Fail closed at the door: without a key there is no coverage to apply and no plan to meter, so
  // the only safe thing is to refuse rather than proxy an ATS straight into a model.
  log("PII_SHIELD_KEY is not set. Refusing to start: without it nothing would be redacted.");
  process.exit(2);
}

// ── configuration, fetched once from the workspace ─────────────────────────────────────────────
/**
 * The workspace's own coverage — the same config the dashboard, extension and gateway use, so a
 * rule added once applies here too. Fails closed: an invalid key stops the wrapper rather than
 * silently falling back to defaults the workspace never chose.
 */
async function loadConfig() {
  const res = await fetch(`${ORIGIN}/api/ext/config?key=${encodeURIComponent(KEY)}`).catch((e) => {
    throw new Error(`could not reach ${ORIGIN}: ${e.message}`);
  });
  const d = await res.json().catch(() => ({}));
  if (!d || d.ok === false) throw new Error(`the workspace key was rejected (${d?.reason || "unknown"})`);
  return {
    config: { ...DEFAULT_CONFIG, ...(d.config || {}) },
    overLimit: !!d.overLimit,
    plan: d.plan,
  };
}

/**
 * Report what was masked so it counts toward the plan, exactly like every other surface.
 *
 * The reply also tells us whether that request exhausted the plan, which is the only way this
 * process learns about it: quota was checked once at startup, so a long-lived agent session could
 * otherwise run for hours after the plan ran out. Reading it here means the NEXT tool call fails
 * closed instead.
 */
function meter(count, counts) {
  if (!count) return;
  fetch(`${ORIGIN}/api/ext/usage`, {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ key: KEY, count, counts, source: "cli", client: "mcp-wrap" }),
  }).then((r) => r.json()).then((d) => {
    if (d && d.overLimit && !OVER_LIMIT) { OVER_LIMIT = true; log("plan limit reached - further tool calls will error rather than return data"); }
  }).catch(() => { /* metering must never break a tool call */ });
}

// ── redaction over a JSON structure ────────────────────────────────────────────────────────────
/**
 * Walk every string in a structure and redact it through ONE session.
 *
 * Structure-preserving on purpose: an MCP client parses these results, so flattening a record to
 * text would break the tool contract. Keys are left alone — a key is a field name, not data, and
 * rewriting `email_addresses` would make the payload unreadable to the agent.
 */
/**
 * `key` is the key this value arrived under, and it is not decoration: a bare given name has no
 * shape to detect, so for `{"first_name": "Jennifer"}` the key IS the evidence. Walking to the leaf
 * and calling redactText("Jennifer") throws that away, which is how Greenhouse records with the
 * name split across first_name/last_name used to pass through whole.
 *
 * Array elements inherit the key of the array they are in, so `{"names": ["Jennifer", "Sipho"]}`
 * keeps the signal for every element.
 */
function redactDeep(value, session, key) {
  if (typeof value === "string") return session.redactField(key, value);
  if (Array.isArray(value)) return value.map((v) => redactDeep(v, session, key));
  if (value && typeof value === "object") {
    const out = {};
    for (const [k, v] of Object.entries(value)) out[k] = redactDeep(v, session, k);
    return out;
  }
  return value;
}

/**
 * Redact only free-text description fields, leaving every other part of a listing alone.
 *
 * A tool's NAME and its JSON schema are the contract the agent calls against; rewriting either
 * breaks it, and there is no PII in a schema. A description is prose, and a server that mints a
 * tool per candidate puts the candidate in it.
 */
const DESCRIPTION_KEYS = new Set(["description", "title", "summary", "instructions"]);
function redactDescriptions(value, session) {
  if (Array.isArray(value)) return value.map((v) => redactDescriptions(v, session));
  if (value && typeof value === "object") {
    const out = {};
    for (const [k, v] of Object.entries(value)) {
      out[k] = DESCRIPTION_KEYS.has(k) && typeof v === "string"
        ? session.redactField(k, v)
        : redactDescriptions(v, session);
    }
    return out;
  }
  return value;
}

/** The mirror image: put real values back into arguments the model is sending upstream. */
function rehydrateDeep(value, session) {
  if (typeof value === "string") return session.rehydrate(value);
  if (Array.isArray(value)) return value.map((v) => rehydrateDeep(v, session));
  if (value && typeof value === "object") {
    const out = {};
    for (const [k, v] of Object.entries(value)) out[k] = rehydrateDeep(v, session);
    return out;
  }
  return value;
}

// ── main ───────────────────────────────────────────────────────────────────────────────────────
const boot = await loadConfig().catch((e) => { log(e.message); process.exit(2); });
const session = new RedactionSession(boot.config);
OVER_LIMIT = boot.overLimit;
log(`shield active · plan ${boot.plan || "?"}${OVER_LIMIT ? " · OVER LIMIT (tool calls will error)" : ""}`);

const child = spawn(upstreamArgv[0], upstreamArgv.slice(1), {
  stdio: ["pipe", "pipe", "inherit"],   // the upstream's stderr goes straight to ours
  env: process.env,
});
child.on("error", (e) => { log(`could not start the upstream server: ${e.message}`); process.exit(1); });
child.on("exit", (code, signal) => {
  debug(`upstream exited (${signal || code})`);
  process.exit(typeof code === "number" ? code : 1);
});

/** Which in-flight request ids are tool calls / resource reads, i.e. the ones whose results carry data. */
const dataCalls = new Map();   // id -> tool name

const send = (stream, msg) => stream.write(JSON.stringify(msg) + "\n");

/**
 * A newline-delimited JSON reader. MCP stdio framing is one JSON message per line, and a chunk can
 * split a message anywhere — including mid-multibyte-character — so the buffer is decoded as a
 * string and only whole lines are parsed.
 */
function lines(stream, onMessage) {
  let buf = "";
  stream.setEncoding("utf8");
  stream.on("data", (chunk) => {
    buf += chunk;
    let i;
    while ((i = buf.indexOf("\n")) >= 0) {
      const line = buf.slice(0, i).trim();
      buf = buf.slice(i + 1);
      if (!line) continue;
      let msg;
      try { msg = JSON.parse(line); }
      catch { debug("dropping a line that is not JSON"); continue; }
      onMessage(msg, line);
    }
  });
}

// ── model ──▶ upstream ─────────────────────────────────────────────────────────────────────────
lines(process.stdin, (msg) => {
  const m = msg.method || "";
  // Everything that can carry a record. `resources/list` was missed, and it is the worst one to
  // miss: an ATS that exposes CVs as resources hands over the entire candidate roster — names in
  // `name`, addresses in `uri`, names again in `description` — at the handshake, before a single
  // tool is called. `resources/read` was already covered, which is what made the gap invisible.
  const carriesData = m === "tools/call" || m === "resources/read" || m === "resources/list"
    || m === "resources/templates/list" || m === "prompts/list" || m === "prompts/get";
  // Tool and prompt LISTINGS carry free-text descriptions, which a server that generates a tool per
  // candidate will fill with candidate names. Names and schemas still pass through byte-for-byte —
  // rewriting those would break the agent — but the prose beside them is redacted like any prose.
  const carriesDescriptions = m === "tools/list";
  if ((carriesData || carriesDescriptions) && msg.id !== undefined) {
    dataCalls.set(msg.id, { tool: msg.params?.name || m, descriptionsOnly: !carriesData });
  }

  // Refuse a data call we cannot redact, rather than letting it through unshielded.
  if (carriesData && OVER_LIMIT) {
    send(process.stdout, {
      jsonrpc: "2.0", id: msg.id,
      result: {
        content: [{ type: "text", text: "PII Shield: this workspace has reached its plan limit, so the result was not returned. Upgrade or add credits to continue." }],
        isError: true,
      },
    });
    dataCalls.delete(msg.id);
    return;
  }

  // The model only ever saw tokens, so restore the real values before the ATS sees them.
  const out = carriesData && msg.params ? { ...msg, params: rehydrateDeep(msg.params, session) } : msg;
  send(child.stdin, out);
});

// ── upstream ──▶ model ─────────────────────────────────────────────────────────────────────────
lines(child.stdout, (msg) => {
  const call = msg.id !== undefined ? dataCalls.get(msg.id) : undefined;
  const tool = call?.tool;
  if (call === undefined || !msg.result) {
    // Protocol traffic with nothing to scan: initialize, notifications, errors. Passed through
    // untouched. Tool names and JSON schemas are the contract the agent calls against and rewriting
    // one breaks it; their free-text DESCRIPTIONS are handled above, because a server that mints a
    // tool per candidate puts the candidate in them.
    send(process.stdout, msg);
    return;
  }
  dataCalls.delete(msg.id);

  const before = session.total;
  let result;
  try {
    result = call.descriptionsOnly
      ? redactDescriptions(msg.result, session)
      : redactDeep(msg.result, session);
  } catch (e) {
    // Fail closed. A redaction that throws must not become a raw record on its way to a model.
    log(`redaction failed for ${tool}: ${e.message}`);
    send(process.stdout, {
      jsonrpc: "2.0", id: msg.id,
      result: { content: [{ type: "text", text: `PII Shield could not redact this ${tool} result, so it was withheld.` }], isError: true },
    });
    return;
  }
  const masked = session.total - before;
  if (masked) {
    const counts = {};
    for (const f of session.findingList()) counts[f.type] = (counts[f.type] || 0) + 1;
    meter(masked, counts);
    debug(`${tool}: masked ${masked} value(s)`);
  }
  send(process.stdout, { ...msg, result });
});

process.stdin.on("end", () => { try { child.stdin.end(); } catch { /* already gone */ } });
for (const sig of ["SIGINT", "SIGTERM"]) process.on(sig, () => { try { child.kill(sig); } catch { /* gone */ } });
