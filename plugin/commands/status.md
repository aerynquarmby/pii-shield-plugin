---
description: Show your PII Shield plan — monthly usage and pay-as-you-go credits remaining
disable-model-invocation: true
---

```!
node "${CLAUDE_PLUGIN_ROOT}/lib/status.mjs"
```

Relay the PII Shield status above to me verbatim. Do not add analysis unless the status shows a warning or that protection is paused, in which case explain briefly what to do.

The report ends with the reminder that detection is automated and is not a guarantee: it can miss
personal data, so always review what you send to an AI.
