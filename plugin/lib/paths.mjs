/** Where the CLI integrations keep per-session state and the cached billing gate. */
import path from "node:path";
import os from "node:os";

export const STATE_DIR = process.env.PII_SHIELD_STATE_DIR
  || path.join(process.env.CLAUDE_PLUGIN_DATA || os.tmpdir(), "pii-shield-state");
