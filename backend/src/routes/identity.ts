import { Hono } from "hono";
import { csrfProtection } from "../middleware/csrf";
import {
  handleGetRegistrationConfig,
  handleGetRegistrationIntentStatus,
} from "./identity-registration-shared";
import {
  handleRegistrationStart,
  handleRegistrationResend,
} from "./identity-registration";
import { handleRegistrationVerify } from "./identity-registration-verify";
import { handleMailCallback } from "../identity/mail-webhooks";

const identity = new Hono();

identity.use("*", async (c, next) => {
  c.header("Cache-Control", "no-store");
  await next();
});

identity.use("/registration/*", csrfProtection);

identity.get("/registration/config", handleGetRegistrationConfig);
identity.get("/registration/intent/:intentId", handleGetRegistrationIntentStatus);
identity.post("/registration/start", handleRegistrationStart);
identity.post("/registration/resend", handleRegistrationResend);
identity.post("/registration/verify", handleRegistrationVerify);

identity.post("/mail/callbacks", handleMailCallback);

export default identity;
