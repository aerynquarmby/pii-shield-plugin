#!/usr/bin/env node
/**
 * SessionEnd — keep the sealed map if the workspace asked for one, then delete the plaintext map.
 *
 * The sidecar is plaintext PII. It exists only so redaction stays stable within a session, and it
 * should not outlive it. If SessionEnd never fires (crash, kill -9), session-store's TTL sweep
 * removes it on the next run.
 *
 * Before deleting, and only when the workspace has turned it on, the same map is sealed on this
 * machine and filed so a file redacted in this session can be restored later. Sealing first and
 * deleting second is deliberate: the plaintext copy is what we are trying to be rid of, so it goes
 * whether or not the upload succeeded.
 */
import fs from "node:fs";
import { destroy, load, configFromGate } from "../lib/session-store.mjs";
import { resolveGate } from "../lib/gate.mjs";
import { keepSessionMap } from "../lib/token-maps.mjs";

try {
  const input = JSON.parse(fs.readFileSync(0, "utf8"));
  try {
    const gate = await resolveGate();
    if (gate?.open && gate.keepTokenMaps) {
      await keepSessionMap(load(input.session_id, configFromGate(gate)), gate);
    }
  } catch { /* never let keeping a map delay or block the cleanup below */ }
  destroy(input.session_id);
} catch { /* nothing to clean */ }
process.exit(0);
