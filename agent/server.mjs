import { makeApp, resolveAuditMode } from "./app.mjs";
import { buildConfiguredApp } from "./lib/configuredApp.mjs";

const app = buildConfiguredApp(makeApp, { resolveAuditMode });

const port = process.env.PORT ?? 3000;
app.listen(port, () => {
  console.log(`Kokosh agent listening on :${port}`);
});
