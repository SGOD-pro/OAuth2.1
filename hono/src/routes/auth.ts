import { Hono } from "hono";
import { authProvider } from "../utils/auth";

const auth = new Hono();

auth.get("/", (c) => c.json({ status: "ok" }));

auth.all("/*", (c) => {

    const appName =
        c.req.header("x-app-name")

    const appVersion =
        c.req.header("x-app-version")

    const userAgent =
        c.req.header("user-agent")

    const path =
        c.req.path

    const ip =
        c.req.header("x-forwarded-for")

    console.log({
        appName,
        appVersion,
        path,
        ip,
        userAgent,
    })

    return authProvider.handler(c.req.raw);
});

export default auth;