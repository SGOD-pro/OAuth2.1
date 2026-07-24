import { serve } from "@hono/node-server";
import app, { appBootTime } from "./app";

const initMs = Date.now() - appBootTime;
console.log(`Node server init in ${initMs}ms`);

const port = process.env.PORT ? parseInt(process.env.PORT, 10) : 3000;
console.log(`Starting server on port ${port}`);

serve({
  fetch: app.fetch,
  port
});
