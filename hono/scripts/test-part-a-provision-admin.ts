import assert from "node:assert/strict";
import { getDb, closeDb } from "../src/db/mongo";
import { hashPassword } from "better-auth/crypto";
import { ObjectId } from "mongodb";
import { authProvider } from "../src/utils/auth";

process.env.NODE_ENV = "test";
process.env.BETTER_AUTH_SECRET = "a".repeat(32);
process.env.BETTER_AUTH_URL = "http://localhost:3000";
process.env.FRONTEND_URL = "http://localhost:5174";
process.env.TRUSTED_PROXY_CIDRS = "10.0.0.0/8";

const { default: app } = await import("../src/app");

console.log("================================================================");
console.log("  SWYRA AUTH -- PART A: PROVISION-ADMIN ESCALATION AUDIT SUITE");
console.log("================================================================");

const db = await getDb();

// Setup mock clients ClientA and ClientB
const clientAId = "test-client-a-" + Date.now();
const clientBId = "test-client-b-" + Date.now();

await db.collection("oauthClient").insertMany([
  {
    _id: new ObjectId(),
    clientId: clientAId,
    name: "Client Alpha",
    redirectUris: ["https://alpha.example.com/callback"],
    allowedOrigins: ["https://alpha.example.com"],
    disabled: false,
    skipConsent: false,
    enableEndSession: true,
    isDev: false,
    createdAt: new Date(),
    updatedAt: new Date(),
  },
  {
    _id: new ObjectId(),
    clientId: clientBId,
    name: "Client Beta",
    redirectUris: ["https://beta.example.com/callback"],
    allowedOrigins: ["https://beta.example.com"],
    disabled: false,
    skipConsent: false,
    enableEndSession: true,
    isDev: false,
    createdAt: new Date(),
    updatedAt: new Date(),
  },
]);

// Helper to create a real user and sign in via Better Auth API
async function createAndLoginAdmin(email: string, role: string, scopedClientId: string | null = null) {
  const password = "ValidAdminPass@1234";

  // Clean existing
  await db.collection("user").deleteMany({ email });
  await db.collection("account").deleteMany({ accountId: email });

  // 1. Sign up
  const signUpRes = await authProvider.api.signUpEmail({
    body: {
      email,
      password,
      name: "Admin " + email,
    },
  });

  const userId = signUpRes.user.id;

  // 2. Set role & scopedClientId in user collection
  await db.collection("user").updateOne(
    { $or: [{ id: userId }, { _id: new ObjectId(userId) }] } as any,
    { $set: { role, scopedClientId } }
  );

  // 3. Sign in to get valid session cookies
  const signInRes = await authProvider.api.signInEmail({
    body: { email, password },
    asResponse: true,
  });

  const cookieHeader = signInRes.headers.get("set-cookie") || "";
  const cookieMatch = cookieHeader.match(/better-auth\.session_token=([^;]+)/);
  const cookie = cookieMatch ? `better-auth.session_token=${cookieMatch[1]}` : "";

  return { userId, email, cookie, cookieHeader };
}

// 1. Super Admin (role: "admin", scopedClientId: null)
const superAdmin = await createAndLoginAdmin("superadmin-" + Date.now() + "@swyra.test", "admin", null);

// 2. App Admin provisioned for ClientA under CURRENT logic (role: "admin", scopedClientId: null or un-enforced)
const currentAppAdmin = await createAndLoginAdmin("appadmin-curr-" + Date.now() + "@swyra.test", "admin", null);

console.log("\n--- TEST 1: App Admin lists all clients ---");
{
  const res = await app.request("/api/admin/clients", {
    method: "GET",
    headers: {
      "Origin": "http://localhost:5174",
      "Cookie": currentAppAdmin.cookie,
    },
  });
  console.log(`Current Code Response Status: ${res.status}`);
  const body = await res.json();
  console.log(`Current Code Body Item Count: ${Array.isArray(body) ? body.length : JSON.stringify(body)}`);
  if (res.status === 200) {
    console.log("-> [VULNERABILITY CONFIRMED]: App-admin can view all client applications globally (P0 Escalation)");
  }
}

console.log("\n--- TEST 2: App Admin fetches ClientB (unowned) config ---");
{
  const res = await app.request(`/api/admin/clients/${clientBId}`, {
    method: "GET",
    headers: {
      "Origin": "http://localhost:5174",
      "Cookie": currentAppAdmin.cookie,
    },
  });
  console.log(`Current Code Response Status: ${res.status}`);
  const body = await res.json();
  console.log(`Response Body: ${JSON.stringify(body)}`);
  if (res.status === 200) {
    console.log("-> [VULNERABILITY CONFIRMED]: App-admin can inspect other clients' configuration");
  }
}

console.log("\n--- TEST 3: App Admin calls POST /admin/users to provision another admin ---");
{
  const res = await app.request("/api/admin/users", {
    method: "POST",
    headers: {
      "Origin": "http://localhost:5174",
      "Content-Type": "application/json",
      "Cookie": currentAppAdmin.cookie,
    },
    body: JSON.stringify({
      email: `rogue-admin-${Date.now()}@swyra.test`,
      password: "RoguePassword123!",
      name: "Rogue Admin",
      clientId: clientBId,
    }),
  });
  console.log(`Current Code Response Status: ${res.status}`);
  const body = await res.json();
  console.log(`Response Body: ${JSON.stringify(body)}`);
  if (res.status === 200) {
    console.log("-> [VULNERABILITY CONFIRMED]: App-admin can provision arbitrary new admins (Recursive Escalation)");
  }
}

console.log("\n--- TEST 4: App Admin deletes ClientB (unowned) ---");
{
  const res = await app.request(`/api/admin/clients/${clientBId}`, {
    method: "DELETE",
    headers: {
      "Origin": "http://localhost:5174",
      "Cookie": currentAppAdmin.cookie,
    },
  });
  console.log(`Current Code Response Status: ${res.status}`);
  const body = await res.json();
  console.log(`Response Body: ${JSON.stringify(body)}`);
  if (res.status === 200) {
    console.log("-> [VULNERABILITY CONFIRMED]: App-admin can delete clients they do not own");
  }
}

console.log("\n--- TEST 6: Weak Password on POST /admin/users ---");
{
  const res = await app.request("/api/admin/users", {
    method: "POST",
    headers: {
      "Origin": "http://localhost:5174",
      "Content-Type": "application/json",
      "Cookie": superAdmin.cookie,
    },
    body: JSON.stringify({
      email: `weakpass-admin-${Date.now()}@swyra.test`,
      password: "aaaaaaaaaaaa1", // 13 chars, lacks uppercase & special symbol
      name: "Weak Admin",
      clientId: clientAId,
    }),
  });
  console.log(`Response Status with 'aaaaaaaaaaaa1': ${res.status}`);
  const body = await res.json();
  console.log(`Response Body: ${JSON.stringify(body)}`);
  if (res.status === 200) {
    console.log("-> [VULNERABILITY CONFIRMED]: POST /admin/users accepts weak passwords bypassing complexity validation");
  }
}

console.log("\n--- TEST 7: Rate Limit on POST /admin/users ---");
{
  let throttled = false;
  let count = 0;
  for (let i = 0; i < 20; i++) {
    const res = await app.request("/api/admin/users", {
      method: "POST",
      headers: {
        "Origin": "http://localhost:5174",
        "Content-Type": "application/json",
        "Cookie": superAdmin.cookie,
      },
      body: JSON.stringify({
        email: `flood-admin-${i}-${Date.now()}@swyra.test`,
        password: "ValidPassword@123!",
        name: `Flood Admin ${i}`,
        clientId: clientAId,
      }),
    });
    if (res.status === 429) {
      throttled = true;
      break;
    }
    if (res.status === 200) count++;
  }
  console.log(`Completed ${count} requests without 429 rate limit (Throttled: ${throttled})`);
  if (!throttled) {
    console.log("-> [VULNERABILITY CONFIRMED]: POST /admin/users is not rate limited");
  }
}

// Cleanup
await db.collection("oauthClient").deleteMany({ clientId: { $in: [clientAId, clientBId] } });
await db.collection("user").deleteMany({ email: { $regex: /@swyra\.test$/ } });
await db.collection("account").deleteMany({ accountId: { $regex: /@swyra\.test$/ } });
await db.collection("session").deleteMany({ token: { $regex: /^test-session-/ } });

await closeDb();
console.log("\nAudit of Part A completed.");
