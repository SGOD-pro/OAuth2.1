import { serve } from "@hono/node-server";
import app, { appBootTime } from "./app";
import { config } from "./config";

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
