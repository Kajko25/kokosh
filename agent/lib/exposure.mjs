import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";

const REPORT_PATH = fileURLToPath(new URL("../../docs/approvals-report.json", import.meta.url));

export async function readExposureReport() {
  try {
    const raw = await readFile(REPORT_PATH, "utf8");
    return JSON.parse(raw);
  } catch {
    return null;
  }
}
