import { makeApp, resolveAuditMode } from "../app.mjs";
import { buildConfiguredApp } from "../lib/configuredApp.mjs";

export default buildConfiguredApp(makeApp, { resolveAuditMode });
