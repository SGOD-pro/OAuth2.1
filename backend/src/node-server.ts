import { serve } from "@hono/node-server";
import app, { appBootTime } from "./app";
import { config } from "./config";
import { startDeletionReconcileWorker } from "./workers/deletion";
import { startExportWorker } from "./workers/export";

const initMs = Date.now() - appBootTime;
console.log(`Node server init in ${initMs}ms`);

const port = config.port || 3000;
const host = process.env.HOST || "0.0.0.0";
console.log(`Starting server on ${host}:${port}`);

serve({
  fetch: app.fetch,
  port,
  hostname: host,
});

if (config.env !== "test" && config.identity.deletionReconcileEnabled) {
  startDeletionReconcileWorker({ intervalMs: config.identity.deletionReconcileIntervalMs });
}
if (config.env !== "test") {
  startExportWorker({ intervalMs: 5000 });
}
