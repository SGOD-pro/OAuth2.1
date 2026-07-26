import { Hono } from "hono";
const test = new Hono();
test.get("/error", (c) => {
  throw new Error("Test error");
});
export default test;
