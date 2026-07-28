import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";

// Inside the agent package on purpose: agent/ is the Vercel project root, so anything above
// it is simply not deployed. While this lived in docs/, /exposure answered "not_scanned_yet"
// in production forever and /audit sold a report whose exposure section was always empty.
const REPORT_PATH = fileURLToPath(new URL("../data/approvals-report.json", import.meta.url));

/**
 * Read the committed approval snapshot.
 *
 * Returns null when there is no usable report, which /exposure surfaces as 202
 * "not_scanned_yet". The distinction that matters is *why*: a missing file is the normal
 * pre-first-scan state, while unreadable or malformed JSON, or a file missing the arrays the
 * callers index into, is a broken deployment. The original version caught everything and
 * returned null silently, so a corrupted report was indistinguishable from never having run
 * the scanner — and the endpoint would have reported "not scanned yet" forever.
 */
export async function readExposureReport({ path = REPORT_PATH, log = console.warn } = {}) {
  let raw;
  try {
    raw = await readFile(path, "utf8");
  } catch (err) {
    if (err?.code !== "ENOENT") log(`exposure report unreadable at ${path}: ${err?.message ?? err}`);
    return null;
  }

  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    log(`exposure report is not valid JSON: ${err?.message ?? err}`);
    return null;
  }

  if (!Array.isArray(parsed?.erc20Live) || !Array.isArray(parsed?.permit2Live)) {
    log("exposure report is missing erc20Live/permit2Live arrays — treating as unscanned");
    return null;
  }

  return parsed;
}
