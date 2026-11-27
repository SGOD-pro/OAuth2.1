import { serve } from "@hono/node-server";
import app, { appBootTime } from "./app";
import { config } from "./config";
import { startDeletionReconcileWorker } from "./workers/deletion";
import { startExportWorker } from "./workers/export";

serve({ fetch: app.fetch, port: config.port }, (info) => {
  const bootMs = Date.now() - appBootTime;
  console.log(`App booted in ${bootMs}ms`);
  console.log(`Server running on http://localhost:${info.port}`);
});

if (config.env !== "test" && config.identity.deletionReconcileEnabled) {
  startDeletionReconcileWorker({ intervalMs: config.identity.deletionReconcileIntervalMs });
}
if (config.env !== "test") {
  startExportWorker({ intervalMs: 5000 });
}

