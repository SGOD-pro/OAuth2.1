import { handle } from "hono/vercel";
import app, { appBootTime } from "./app";

const initMs = Date.now() - appBootTime;
console.log(`Vercel init in ${initMs}ms`);

export default handle(app);
