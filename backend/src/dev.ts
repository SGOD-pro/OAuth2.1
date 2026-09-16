import { serve } from "@hono/node-server";
import app, { appBootTime } from "./app";
import { config } from "./config";

serve({ fetch: app.fetch, port: config.port }, (info) => {
  const bootMs = Date.now() - appBootTime;
  console.log(`App booted in ${bootMs}ms`);
  console.log(`Server running on http://localhost:${info.port}`);
});

