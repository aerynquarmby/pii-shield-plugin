#!/usr/bin/env node
/**
 * SessionEnd — delete the token map.
 *
 * The map is plaintext PII. It exists only so redaction stays stable within a session,
 * and it should not outlive it. If SessionEnd never fires (crash, kill -9), session-store's
 * TTL sweep removes it on the next run.
 */
import fs from "node:fs";
import { destroy } from "../lib/session-store.mjs";

try {
  const input = JSON.parse(fs.readFileSync(0, "utf8"));
  destroy(input.session_id);
} catch { /* nothing to clean */ }
process.exit(0);
