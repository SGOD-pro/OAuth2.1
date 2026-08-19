process.env.NODE_ENV = "test";
process.env.MONGO_URI = "mongodb+srv://testing938212:Jarvis123@cluster0.df3gouo.mongodb.net/oauthservice";
process.env.BETTER_AUTH_SECRET = "a".repeat(32);
process.env.BETTER_AUTH_URL = "http://localhost:3000";
process.env.GOOGLE_CLIENT_ID = "test-google-id";
process.env.GOOGLE_CLIENT_SECRET = "test-google-secret";
process.env.FRONTEND_URL = "http://localhost:5174";
process.env.TRUSTED_PROXY_CIDRS = "10.0.0.0/8";

const { default: app } = await import("../src/app");
const { authProvider } = await import("../src/utils/auth");

console.log("==================================================================");
console.log(" ROOT-CAUSE REPRODUCTION: GET /api/admin/clients/:id");
console.log(` Timestamp: ${new Date().toISOString()}`);
console.log("==================================================================\n");

// 1. Test without admin session
console.log("1. Calling GET /api/admin/clients/test-id without session:");
const res1 = await app.request("/api/admin/clients/test-id", {
  method: "GET",
  headers: { Origin: "http://localhost:5174" },
});
console.log(`   Status: ${res1.status}`);
console.log(`   Body:   ${await res1.text()}\n`);

// 2. Direct test of authProvider.api.getOAuthClient with non-existent client ID
console.log("2. Direct call to authProvider.api.getOAuthClient({ query: { client_id: 'non_existent_client_xyz' } }):");
try {
  const res = await authProvider.api.getOAuthClient({
    query: { client_id: "non_existent_client_xyz" },
  });
  console.log("   Result:", res);
} catch (err: any) {
  console.log("   Caught Error Name:", err?.name);
  console.log("   Caught Error Message:", err?.message);
  console.log("   Caught Error Status:", err?.status || err?.statusCode);
  console.log("   Caught Error Constructor:", err?.constructor?.name);
  console.log("   Stack Trace:\n", err?.stack);
}

process.exit(0);
