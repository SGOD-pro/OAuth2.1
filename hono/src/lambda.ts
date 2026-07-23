import { handle } from "hono/aws-lambda";
import app, { appBootTime } from "./app";

const initMs = Date.now() - appBootTime;
console.log(`Lambda init in ${initMs}ms`);

export const handler = handle(app);