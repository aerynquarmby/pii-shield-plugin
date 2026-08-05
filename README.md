# PII Shield — Claude Code plugin

Redacts personal data out of tool output **before it reaches Claude**, and restores the real
values before Claude writes to disk. Everything runs on your machine; nothing is sent to a
redaction service.

```bash
claude plugin marketplace add aerynquarmby/pii-shield-plugin
claude plugin install pii-shield@piishield
```

Then set your workspace key (get one at <https://piishield.ai/signup>):

```bash
export PII_SHIELD_KEY=shield_…      # or write it to ~/.pii-shield/key
```

Why a plugin and not the gateway: on a Claude subscription, Claude Code sends your
**claude.ai account token** to whatever `ANTHROPIC_BASE_URL` points at — never point it at a
redaction proxy. The plugin redacts locally instead, with no credential in flight.

Full setup and options: <https://piishield.ai/guide>

This repository is generated from the PII Shield source. Issues: <https://piishield.ai>
