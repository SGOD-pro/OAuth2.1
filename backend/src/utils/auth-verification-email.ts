import { config } from "../config";

export interface SendVerificationEmailParams {
  user: any;
  url: string;
  token: string;
}

export async function sendVerificationEmailHandler({ user, url, token }: SendVerificationEmailParams): Promise<void> {
  const webhookUrl = config.emailDeliveryWebhookUrl || process.env.EMAIL_DELIVERY_WEBHOOK_URL;
  if (!webhookUrl || typeof webhookUrl !== "string" || !webhookUrl.trim()) {
    if (config.auth.emailVerificationEnabled) {
      console.error("[EMAIL_VERIFICATION] Explicit failure: Email verification is enabled but EMAIL_DELIVERY_WEBHOOK_URL is not configured");
      throw new Error("Email verification is enabled but EMAIL_DELIVERY_WEBHOOK_URL is not configured");
    }
    console.warn("[EMAIL_VERIFICATION] Warning: No external email delivery transport configured for user verification.");
    return;
  }

  let validatedUrl: URL;
  try {
    validatedUrl = new URL(webhookUrl.trim());
  } catch {
    console.error("[EMAIL_VERIFICATION] Invalid EMAIL_DELIVERY_WEBHOOK_URL format");
    throw new Error("Invalid email delivery webhook transport configuration");
  }

  if (config.env === "production") {
    if (validatedUrl.protocol !== "https:") {
      console.error("[EMAIL_VERIFICATION] Insecure transport rejected: EMAIL_DELIVERY_WEBHOOK_URL must use HTTPS in production");
      throw new Error("EMAIL_DELIVERY_WEBHOOK_URL must use HTTPS in production");
    }
    const host = validatedUrl.hostname.toLowerCase().replace(/^\[|\]$/g, "");
    if (host === "localhost" || host === "127.0.0.1" || host === "::1" || host.endsWith(".localhost")) {
      console.error("[EMAIL_VERIFICATION] Insecure transport rejected: EMAIL_DELIVERY_WEBHOOK_URL cannot be loopback in production");
      throw new Error("EMAIL_DELIVERY_WEBHOOK_URL cannot be a loopback address in production");
    }
  }

  try {
    const res = await fetch(validatedUrl.toString(), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: user.email, url, token }),
      signal: AbortSignal.timeout(5000),
    });

    if (!res.ok) {
      console.error(`[EMAIL_VERIFICATION] Email delivery webhook failed with status ${res.status}`);
      throw new Error(`Email delivery webhook failed with HTTP ${res.status}`);
    }
  } catch (err: any) {
    if (err.name === "TimeoutError" || err.name === "AbortError" || err.message?.includes("timed out")) {
      console.error("[EMAIL_VERIFICATION] Delivery webhook timed out after 5000ms");
      throw new Error("Email delivery timed out");
    }
    if (err.message?.includes("HTTP") || err.message?.includes("HTTPS") || err.message?.includes("loopback")) {
      throw err;
    }
    console.error("[EMAIL_VERIFICATION] Delivery webhook network error");
    throw new Error("Email delivery transport network failure");
  }
}
