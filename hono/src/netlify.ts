import { handle } from "hono/netlify";
import app, { appBootTime } from "./app";

const initMs = Date.now() - appBootTime;
console.log(`Netlify init in ${initMs}ms`);

export default handle(app);
