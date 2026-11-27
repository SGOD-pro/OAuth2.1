import http from "node:http";
import { getRequestListener } from "@hono/node-server";

let requestHandler: ((req: http.IncomingMessage, res: http.ServerResponse) => void) | null = null;

const server = http.createServer((req, res) => {
  if (!requestHandler) {
    res.statusCode = 503;
    res.end("IdP initializing");
    return;
  }
  requestHandler(req, res);
});

await new Promise<void>((resolve, reject) => {
  server.once("error", reject);
  server.listen(0, "127.0.0.1", () => resolve());
});

const addr = server.address();
if (!addr || typeof addr === "string") {
  throw new Error("Failed to resolve bound IdP port");
}

const idpUrl = `http://127.0.0.1:${addr.port}`;
process.env.PORT = String(addr.port);
process.env.BETTER_AUTH_URL = idpUrl;

const { default: app } = await import("../../src/app");
requestHandler = getRequestListener(app.fetch);

process.send?.({ type: "ready", port: addr.port, idpUrl });
