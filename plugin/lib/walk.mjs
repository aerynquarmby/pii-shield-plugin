/**
 * Type-preserving string walker.
 *
 * Why this exists: Claude Code silently discards a PostToolUse `updatedToolOutput`
 * whose type does not match the original `tool_response`. `tool_response` for Read is
 * an object; coercing it to a string makes the hook fail open — the unredacted result
 * reaches the API with no error. See tools/canary/FINDINGS.md §2.
 *
 * So: never JSON.stringify a tool_response. Map its string leaves in place.
 */

/**
 * Structural fields that carry meaning to Claude Code rather than content to the model.
 * Rewriting them breaks tool semantics (a redacted filePath is a path that no longer exists),
 * and they are echoed back on the next request from the tool_use block anyway.
 */
export const STRUCTURAL_KEYS = new Set([
  "filePath", "file_path", "path", "type", "numLines", "startLine", "totalLines",
  "originalFile", "userModified", "interrupted", "isImage", "returnCodeInterpretation",
]);

/**
 * Base64-encoded binary — an image, a PDF, any file bytes a tool returns. It must pass through
 * UNTOUCHED: redacting a token inside it (or replacing it wholesale when we withhold) corrupts
 * the blob, and the model drops it with "an image could not be processed and was removed". Real
 * PII is short prose, never a long continuous base64 run, so skipping these loses no coverage.
 * Redaction of images is the document tool's job (OCR), not a fast per-tool hook's.
 */
const BASE64_BLOB = /^[A-Za-z0-9+/]{120,}={0,2}$/;
export function isBinaryBlob(s) {
  return typeof s === "string" && s.length >= 120 &&
    (BASE64_BLOB.test(s) || /^data:[^,]*;base64,/i.test(s));
}

/** Map every string leaf with `fn`, preserving the node's original type and shape. */
export function mapStrings(node, fn, key = null) {
  if (typeof node === "string") return (STRUCTURAL_KEYS.has(key) || isBinaryBlob(node)) ? node : fn(node);
  if (Array.isArray(node)) return node.map((n) => mapStrings(n, fn, key));
  if (node && typeof node === "object") {
    const out = {};
    for (const [k, v] of Object.entries(node)) out[k] = mapStrings(v, fn, k);
    return out;
  }
  return node;
}

/** Cheap structural equality, used to decide whether a hook needs to emit anything at all. */
export const unchanged = (a, b) => JSON.stringify(a) === JSON.stringify(b);
