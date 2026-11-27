import assert from "node:assert/strict";
import { describe, it } from "node:test";

process.env.NODE_ENV = process.env.NODE_ENV || "test";
process.env.MONGO_URI = process.env.MONGO_URI || "mongodb://127.0.0.1:27017/unused";
process.env.BETTER_AUTH_SECRET = process.env.BETTER_AUTH_SECRET || "s".repeat(32);
process.env.BETTER_AUTH_URL = process.env.BETTER_AUTH_URL || "http://localhost:3000";
process.env.GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || "test-google-id";
process.env.GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET || "test-google-secret";
process.env.FRONTEND_URL = process.env.FRONTEND_URL || "http://localhost:5174";
process.env.INTERNAL_GATEWAY_SECRET = process.env.INTERNAL_GATEWAY_SECRET || "g".repeat(32);

const {
  digestDeviceId,
  evaluateSessionDeviceRisk,
  extractCoarseDeviceSignals,
  parseCoarseIpPrefix,
  parseCoarseUaFamily,
} = await import("../../src/identity/device-risk");

describe("P8 Coarse Device Risk (Stolen Session Prevention)", () => {
  it("allows VPN/IP drift when device cookie matches and allows cookie reset on same browser/network", () => {
    const bound = {
      deviceKeyDigest: digestDeviceId("device-cookie-1234567890"),
      uaFamily: "chrome:linux",
      ipPrefix: "198.51.100.0/24",
    };

    // VPN IP drift with matching device cookie -> normal
    const vpnDrift = evaluateSessionDeviceRisk({
      bound,
      current: {
        deviceKeyDigest: digestDeviceId("device-cookie-1234567890"),
        uaFamily: "chrome:linux",
        ipPrefix: "203.0.113.0/24",
      },
    });
    assert.equal(vpnDrift.level, "normal");

    // Cleared device cookie on same browser and same network -> normal (no brittle ban)
    const cookieReset = evaluateSessionDeviceRisk({
      bound,
      current: {
        deviceKeyDigest: null,
        uaFamily: "chrome:linux",
        ipPrefix: "198.51.100.0/24",
      },
    });
    assert.equal(cookieReset.level, "normal");
  });

  it("flags elevated risk when stolen session cookie is pasted into a different browser on same network", () => {
    const bound = {
      deviceKeyDigest: digestDeviceId("victim-device-cookie-1234"),
      uaFamily: "chrome:linux",
      ipPrefix: "198.51.100.0/24",
    };

    const stolenSameNet = evaluateSessionDeviceRisk({
      bound,
      current: {
        deviceKeyDigest: null,
        uaFamily: "firefox:windows",
        ipPrefix: "198.51.100.0/24",
      },
    });
    assert.equal(stolenSameNet.level, "elevated");
    assert.ok(stolenSameNet.reasons.includes("ua_family_changed"));
  });

  it("flags high risk when stolen session cookie is replayed from different browser and different network", () => {
    const bound = {
      deviceKeyDigest: digestDeviceId("victim-device-cookie-1234"),
      uaFamily: "chrome:linux",
      ipPrefix: "198.51.100.0/24",
    };

    const stolenRemote = evaluateSessionDeviceRisk({
      bound,
      current: {
        deviceKeyDigest: digestDeviceId("attacker-device-cookie-9999"),
        uaFamily: "safari:macos",
        ipPrefix: "203.0.113.0/24",
      },
    });
    assert.equal(stolenRemote.level, "high");
    assert.ok(stolenRemote.reasons.includes("device_cookie_mismatch"));
    assert.ok(stolenRemote.reasons.includes("ua_family_changed"));
    assert.ok(stolenRemote.reasons.includes("ip_prefix_changed"));
  });

  it("extracts coarse UA family and IP prefix without storing raw IP or raw device token", () => {
    assert.equal(parseCoarseUaFamily("Mozilla/5.0 (X11; Linux x86_64) Chrome/120.0.0.0"), "chrome:linux");
    assert.equal(parseCoarseIpPrefix("198.51.100.42"), "198.51.100.0/24");

    const h = new Headers({
      "user-agent": "Mozilla/5.0 (Windows NT 10.0) Firefox/121.0",
      "x-forwarded-for": "203.0.113.77",
    });
    const sig = extractCoarseDeviceSignals(h, "raw-secret-device-token-1234", ["0.0.0.0/0"]);
    assert.equal(sig.uaFamily, "firefox:windows");
    assert.equal(sig.ipPrefix, "203.0.113.0/24");
    assert.ok(sig.deviceKeyDigest && !sig.deviceKeyDigest.includes("raw-secret-device-token"));
  });
});
