# PII Shield for Claude Code

Redacts personal data out of tool output before Claude sees it, and puts the real values
back before Claude writes to disk. Everything runs on your machine. No text is sent to a
redaction service, and no credential leaves your machine.

## Install

```bash
claude plugin marketplace add aerynquarmby/pii-shield-plugin
claude plugin install pii-shield@piishield
export PII_SHIELD_KEY=shield_your_workspace_key    # or: echo shield_… > ~/.pii-shield/key
```

Nothing to download first — `marketplace add` clones the repo itself. The hooks register
themselves; you do not edit `settings.json`.

### Getting your workspace key

1. Sign up at <https://piishield.ai/signup>.
2. **Confirm your email.** Signing up does not hand over a key: we mail you a link, and the
   workspace only activates when you click it. That is deliberate — anyone can type anyone's
   address into a form, so the key is never sent to whoever filled it in, only to the mailbox
   that owns the address. The key is not in the email either; an API key should not sit in an
   inbox.
3. Copy the key from your dashboard, under **Integration**.

The key is required. Like the browser extension, the plugin redacts only with a **valid,
in-quota workspace key**, and it **fails closed**: without one, tool output containing personal
data is withheld from Claude rather than passed through. Free plan is 250 requests/month.


## Detection is not a guarantee

PII Shield's detection is automated. It is a heuristic, not a proof: **it can miss personal data**,
and it can mask things that were not personal data at all. A clean result is not a certificate.

**Always review what you send to an AI.** PII Shield reduces the risk of a leak; it does not remove
it, and you use it at your own risk.

## What it covers — and what it cannot

Measured against Claude Code 2.1.205. Re-run `npm run verify:plugin` to confirm on your version.

| Where personal data enters | Covered? | How |
| --- | --- | --- |
| `Read` file contents | **yes** | redacted before entering context |
| `Bash` stdout | **yes** | redacted before entering context |
| `Grep` / `Glob` / `WebFetch` output | **yes** | redacted before entering context |
| MCP tool results | **yes** | redacted before entering context |
| `Write` / `Edit` content → disk | **yes** | tokens restored to real values |
| What you type or paste | **blocked, not redacted** | Claude Code does not let a hook rewrite a prompt |
| `@`-mentioned files | **blocked, not redacted** | contents are expanded after every hook has run |

**Claude Code cannot redact prompts.** `UserPromptSubmit` may block a prompt or add context;
it cannot replace the text. So a prompt containing personal data is rejected with an
explanation rather than quietly cleaned. If you want the file read, let Claude use the `Read`
tool on it instead of `@`-mentioning it — tool output *is* redacted.

**Claude Code puts your account email in every request.** That is Anthropic's client, not this
plugin, and no hook can intercept it. No integration can truthfully claim "zero PII leaves your
machine" on Claude Code.

## Why hooks and not a proxy

Setting `ANTHROPIC_BASE_URL` to a redacting gateway does two things you do not want. On a
subscription it sends your **claude.ai OAuth account token** to that gateway (measured: `Bearer
sk-ant-oat01-…`, on every request). And Anthropic's gateway protocol requires a gateway to
"inspect without modifying" — a body-rewriting proxy breaks thinking-block signatures and
prompt caching.

Hooks have neither problem. For agents that are not Claude Code, use the local proxy instead:
`npm run local -- --print-setup`.

## Why IP addresses are not redacted by default

The plugin runs the **`code` detector profile**, which turns off `IPV4`, `IPV6`, and `MAC`.
An IPv4 address and a semver are the same four dotted integers, so the full detector set turns
`server listening on 0.0.0.0:8080` into `[IPV4_1]:8080` and `upgraded from 1.2.3.4` into
`[IPV4_1]`. A model that cannot see `127.0.0.1` gives wrong answers.

IP addresses are personal data under GDPR, so the strict set is one variable away:

```bash
export PII_SHIELD_PROFILE=strict
```

## Configuration

Environment variables, all optional:

| Variable | Default | Meaning |
| --- | --- | --- |
| `PII_SHIELD_PROFILE` | `code` | `code` (no IPV4/IPV6/MAC) or `strict` (everything) |
| `PII_SHIELD_PROMPT_MODE` | `block` | `block`, `warn`, or `off` for prompts and `@`-mentions |
| `PII_SHIELD_DETECTORS` | — | explicit comma list; overrides the profile entirely |
| `PII_SHIELD_PERSON` | off | `1` enables heuristic person-name detection |
| `PII_SHIELD_CUSTOM_TERMS` | — | comma list of literals to always mask |
| `PII_SHIELD_ALLOW_TERMS` | — | comma list of values to never mask |
| `PII_SHIELD_STATE_DIR` | temp dir | where the session token map lives |
| `PII_SHIELD_TTL_HOURS` | `24` | sweep abandoned token maps after this long |
| `PII_SHIELD_LEAK_AUDIT` | on | `0` sends nothing to the workspace Leak Audit |

## Check your usage: `/pii-shield:status`

See where you stand at any time — the CLI equivalent of Claude's own usage view:

```
/pii-shield:status
```

```
PII Shield - Trial plan
  This month:    250 / 250 used  (0 left, 100%)
  Pay-as-you-go: 799 credits in reserve
                 monthly allowance is spent; now drawing on credits
  Headroom:      799 redactions before protection pauses
  Status:        ✓ active. PII is being redacted.

  Detection is automated and is not a guarantee. It can miss personal data.
  Always review what you send to an AI. You use it at your own risk.
```

It shows your monthly allowance **and** any pay-as-you-go credits. When the monthly cap is
reached, credits take over automatically — you stay protected until *both* run out. The report
warns when you are low, and tells you what to do if protection has paused.

## Billing

Metered against your plan through the same endpoints the browser extension uses. One unit per
PII-carrying tool output. Usage appears on the dashboard as the `/cli` surface.

Your allowance has two parts, spent in order: the **monthly plan allowance**, then any
**pay-as-you-go credits**. Protection stays active — and metered tools keep working — until both
are exhausted; only then does it pause. Buy credits or change plan on the dashboard Billing tab.

**Only counts leave your machine** — `{count: 2, counts: {EMAIL: 2}}`. Never a value, never the
file. And when a tool result has no personal data in it, no network call happens at all.

Out of quota (monthly **and** credits both gone), no key, or an invalid key: the tool output is
**withheld** and you are told why. It never means "stop redacting and send it anyway". A network
outage does not block you if the key has been validated on this machine before.

## Images and binary files

The plugin redacts **text**. An image or binary file a tool returns (base64) passes through
untouched — it is never rewritten or withheld, so images work normally. Redacting an image needs
OCR, which is the **document tool's** job (dashboard or browser extension), not a fast per-tool
hook. If an image or scanned PDF contains personal data, redact it there first, then attach the
clean copy.

| Variable | Default | Meaning |
| --- | --- | --- |
| `PII_SHIELD_KEY` | — | workspace key; or put it in `~/.pii-shield/key` |
| `PII_SHIELD_API` | `https://piishield.ai` | gateway origin |
| `PII_SHIELD_TIMEOUT_MS` | `3000` | gate call timeout — a hook must never hang a session |
| `PII_SHIELD_REVALIDATE_MS` | `60000` | how often to re-check the plan |

## The token map

Stable tokens require remembering that `[EMAIL_1]` means one specific address for the length of
a session, and rehydration requires reversing it. That map is a plaintext file. It is created
`0600` inside a `0700` directory outside your repo, written by atomic rename, deleted on
`SessionEnd`, and swept after `PII_SHIELD_TTL_HOURS` if the session died without cleanup.

If `redact-output.mjs` throws, it withholds the tool output rather than passing it through.
It fails closed.
