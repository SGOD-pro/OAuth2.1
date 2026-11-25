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
import { handleRegistrationComplete, handleUsernameCheck } from "./identity-registration-complete";
import { handleListBrowserAccounts, handleRemoveBrowserAccount, handleSignOutBrowserAccount } from "./identity-accounts";
import { handleMailCallback } from "../identity/mail-webhooks";

const identity = new Hono();

identity.use("*", async (c, next) => {
  c.header("Cache-Control", "no-store");
  await next();
});

identity.use("/registration/*", csrfProtection);
identity.use("/username/*", csrfProtection);
identity.use("/accounts/*", csrfProtection);

identity.get("/registration/config", handleGetRegistrationConfig);
identity.get("/registration/intent/:intentId", handleGetRegistrationIntentStatus);
identity.post("/registration/start", handleRegistrationStart);
identity.post("/registration/resend", handleRegistrationResend);
identity.post("/registration/verify", handleRegistrationVerify);
identity.post("/registration/complete", handleRegistrationComplete);
identity.post("/username/check", handleUsernameCheck);

identity.get("/accounts", handleListBrowserAccounts);
identity.post("/accounts/sign-out", handleSignOutBrowserAccount);
identity.post("/accounts/remove", handleRemoveBrowserAccount);

identity.post("/mail/callbacks", handleMailCallback);

export default identity;
