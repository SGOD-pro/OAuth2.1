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
import {
  handleListBrowserAccounts,
  handleRemoveBrowserAccount,
  handleSelectBrowserAccount,
  handleSignOutBrowserAccount,
} from "./identity-accounts";
import {
  handleGetOwnerContextMe,
  handleIssueIdentityContext,
  handleRenewIdentityContext,
} from "./identity-contexts";
import { handleClaimInvitation } from "./identity-invitations";
import { handleBackupCodeRecovery, recoveryAccountRateLimit, recoveryIpRateLimit } from "./identity-recovery";
import {
  handleOwnerTotpDisable,
  handleOwnerTotpEnable,
  handleOwnerTotpVerify,
  totpIpRateLimit,
  totpSubjectRateLimit,
} from "./identity-totp";
import { handleMailCallback } from "../identity/mail-webhooks";

const identity = new Hono();

identity.use("*", async (c, next) => {
  c.header("Cache-Control", "no-store");
  await next();
});

identity.use("/registration/*", csrfProtection);
identity.use("/username/*", csrfProtection);
identity.use("/accounts/*", csrfProtection);
identity.use("/contexts", csrfProtection);
identity.use("/contexts/*", csrfProtection);
identity.use("/invitations/*", csrfProtection);
identity.use("/recovery/*", csrfProtection);
identity.use("/totp/*", csrfProtection);

identity.get("/registration/config", handleGetRegistrationConfig);
identity.get("/registration/intent/:intentId", handleGetRegistrationIntentStatus);
identity.post("/registration/start", handleRegistrationStart);
identity.post("/registration/resend", handleRegistrationResend);
identity.post("/registration/verify", handleRegistrationVerify);
identity.post("/registration/complete", handleRegistrationComplete);
identity.post("/username/check", handleUsernameCheck);

identity.get("/accounts", handleListBrowserAccounts);
identity.post("/accounts/select", handleSelectBrowserAccount);
identity.post("/accounts/sign-out", handleSignOutBrowserAccount);
identity.post("/accounts/remove", handleRemoveBrowserAccount);

identity.post("/contexts", handleIssueIdentityContext);
identity.get("/contexts/me", handleGetOwnerContextMe);
identity.post("/contexts/renew", handleRenewIdentityContext);

identity.post("/invitations/claim", handleClaimInvitation);
identity.post("/recovery/backup-code", recoveryIpRateLimit, recoveryAccountRateLimit, handleBackupCodeRecovery);

identity.post("/totp/enable", totpIpRateLimit, handleOwnerTotpEnable);
identity.post("/totp/verify", totpIpRateLimit, totpSubjectRateLimit, handleOwnerTotpVerify);
identity.post("/totp/disable", totpIpRateLimit, totpSubjectRateLimit, handleOwnerTotpDisable);

identity.post("/mail/callbacks", handleMailCallback);

export default identity;
