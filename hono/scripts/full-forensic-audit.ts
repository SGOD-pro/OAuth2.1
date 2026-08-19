import assert from "node:assert/strict";

process.env.NODE_ENV = "test";
process.env.MONGO_URI = "mongodb+srv://testing938212:Jarvis123@cluster0.df3gouo.mongodb.net/oauthservice";
process.env.BETTER_AUTH_SECRET = "a".repeat(32);
process.env.BETTER_AUTH_URL = "http://localhost:3000";
process.env.GOOGLE_CLIENT_ID = "test-google-id";
process.env.GOOGLE_CLIENT_SECRET = "test-google-secret";
process.env.FRONTEND_URL = "http://localhost:5174";
process.env.TRUSTED_PROXY_CIDRS = "10.0.0.0/8";

const { default: app } = await import("../src/app");
const { getDb } = await import("../src/db/mongo");
const { isStrongPassword, validateRedirectUri, safeCallbackURL } = await import("../src/utils/security");

console.log("==================================================================");
console.log(" SWYRA FORENSIC RE-VERIFICATION SUITE");
console.log(` Executed at: ${new Date().toISOString()}`);
console.log("==================================================================\n");

// 1. Part A Check: Current User & Scoping Model
console.log("--- PART A: PROVISION-ADMIN PRIVILEGE ESCALATION STATUS ---");
const db = await getDb();
const sampleUsers = await db.collection("user").find({ role: "admin" }).toArray();
console.log(`Found ${sampleUsers.length} admin accounts in user collection:`);
for (const u of sampleUsers.slice(0, 5)) {
  console.log(`  - email: ${u.email}, role: ${u.role}, scopedClientId: ${u.scopedClientId ?? "UNDEFINED (Global Admin)"}`);
}

// 2. Part A Test 1: Can an unauthenticated user list clients?
const resA1 = await app.request("/api/admin/clients", {
  method: "GET",
  headers: { Origin: "http://localhost:5174" },
});
console.log(`\nPart A Test: Unauthenticated GET /api/admin/clients -> Status: ${resA1.status}`);

// 3. Part B1: JWT alg=none test
console.log("\n--- PART B1: JWT ALGORITHM CONFUSION ---");
const noneToken = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhdGsgifQ.";
const resB1 = await app.request("/api/auth/oauth2/userinfo", {
  method: "GET",
  headers: {
    Authorization: `Bearer ${noneToken}`,
    Origin: "http://localhost:5174",
  },
});
console.log(`B1: GET /api/auth/oauth2/userinfo with alg=none -> Status: ${resB1.status}`);
console.log(`    Response Body: ${await resB1.text()}`);

// 4. Part B3: PKCE Missing on Authorize
console.log("\n--- PART B3: PKCE & STATE ENFORCEMENT ---");
const resB3 = await app.request("/api/auth/oauth2/authorize?client_id=TEST&redirect_uri=http%3A%2F%2Flocalhost%3A3001&response_type=code", {
  method: "GET",
});
console.log(`B3: GET /oauth2/authorize missing state -> Status: ${resB3.status}`);
console.log(`    Location Header: ${resB3.headers.get("Location")}`);

// 5. Part B5: Redirect URI Edge Cases
console.log("\n--- PART B5: REDIRECT URI & CALLBACK EDGE CASES ---");
const edgeCases = [
  "https://app.example.com\\@evil.com/",
  "https://app.example.com.evil.com/",
  "/\\evil.com",
  "https://\u0430pp.example.com/", // Cyrillic homograph
  "https://app.example.com/%2e%2e/",
  "https://app.example.com./cb",
  "javascript:alert(document.cookie)",
];

for (const uri of edgeCases) {
  const validRedirect = validateRedirectUri(uri, { isDev: false, env: "production" });
  const safeCb = safeCallbackURL(uri);
  console.log(`  URI: ${JSON.stringify(uri)} -> validateRedirectUri: ${validRedirect} | safeCallbackURL: ${safeCb ?? "REJECTED"}`);
}

// 6. Part B9: Request Body Size Limit
console.log("\n--- PART B9: BODY SIZE LIMIT (100KB) ---");
const largePayload = JSON.stringify({ data: "X".repeat(110 * 1024) });
const resB9 = await app.request("/api/auth/sign-in/email", {
  method: "POST",
  headers: {
    "Content-Type": "application/json",
    Origin: "http://localhost:5174",
  },
  body: largePayload,
});
console.log(`B9: POST 110KB payload -> Status: ${resB9.status}`);
console.log(`    Response Body: ${await resB9.text()}`);

console.log("\n==================================================================");
console.log(" FORENSIC RE-VERIFICATION SUITE EXECUTION COMPLETED");
console.log("==================================================================");
process.exit(0);
