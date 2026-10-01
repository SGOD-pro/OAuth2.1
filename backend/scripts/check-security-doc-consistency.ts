import fs from "fs";
import path from "path";
import assert from "assert/strict";

console.log("================================================================");
console.log("  SWYRA AUTH -- AUTOMATED SECURITY & DOCUMENTATION CONSISTENCY");
console.log("================================================================");

let errors: string[] = [];

// Determine repository root
const repoRoot = path.resolve(import.meta.dirname, "../..");
const backendRoot = path.resolve(repoRoot, "backend");

function check(desc: string, fn: () => void) {
  try {
    fn();
    console.log(`[PASS] ${desc}`);
  } catch (err: any) {
    console.error(`[FAIL] ${desc}: ${err.message || err}`);
    errors.push(`${desc}: ${err.message || err}`);
  }
}

// 1. Verify Required Canonical Documents and Manifests Exist
check("Required canonical documents exist", () => {
  const requiredFiles = [
    "docs/SECURITY_CANONICAL.md",
    "docs/security/security-suite-manifest.json",
    "docs/security/security-route-manifest.json",
    "docs/AI_AGENT_INTEGRATION_CONTRACT.md",
    "AGENTS.md",
    "README.md",
  ];
  for (const relPath of requiredFiles) {
    const fullPath = path.join(repoRoot, relPath);
    assert.ok(fs.existsSync(fullPath), `Missing required canonical file: ${relPath}`);
  }
});

// 2. Validate Security Suite Manifest vs package.json
check("Security suite manifest matches package.json test scripts", () => {
  const manifestPath = path.join(repoRoot, "docs/security/security-suite-manifest.json");
  const pkgPath = path.join(backendRoot, "package.json");

  const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf-8"));
  const pkg = JSON.parse(fs.readFileSync(pkgPath, "utf-8"));

  assert.ok(manifest.suites && Array.isArray(manifest.suites), "Manifest must contain suites array");
  const blockingSuites = manifest.suites.filter((s: any) => s.blocking === true);

  assert.equal(
    blockingSuites.length,
    manifest.total_blocking_suites,
    `total_blocking_suites (${manifest.total_blocking_suites}) must equal blocking suites count (${blockingSuites.length})`
  );

  const testAllSecurity = pkg.scripts["test:all-security"];
  assert.ok(testAllSecurity, "package.json must contain 'test:all-security' script");

  for (const suite of blockingSuites) {
    assert.ok(
      testAllSecurity.includes(suite.file),
      `test:all-security must execute blocking suite: ${suite.file}`
    );
    const scriptName = suite.command.replace("npm run ", "");
    assert.ok(
      pkg.scripts[scriptName],
      `package.json must define individual script '${scriptName}' for suite ${suite.name}`
    );
  }
});

// 3. Verify Route Manifest Consistency with Codebase
check("Route manifest aligns with backend route implementations", () => {
  const routeManifestPath = path.join(repoRoot, "docs/security/security-route-manifest.json");
  const routeManifest = JSON.parse(fs.readFileSync(routeManifestPath, "utf-8"));

  assert.ok(Array.isArray(routeManifest.routes), "Route manifest must contain routes array");

  // Read backend route source files
  const adminRoutesSrc = fs.readFileSync(path.join(backendRoot, "src/routes/admin.ts"), "utf-8");
  const authRoutesSrc = fs.readFileSync(path.join(backendRoot, "src/routes/auth.ts"), "utf-8");
  const authUtilSrc = fs.readFileSync(path.join(backendRoot, "src/utils/auth.ts"), "utf-8");
  const appAdminSrc = fs.readFileSync(path.join(backendRoot, "src/routes/app-admin-auth.ts"), "utf-8");
  const appSrc = fs.readFileSync(path.join(backendRoot, "src/app.ts"), "utf-8");

  for (const r of routeManifest.routes) {
    if (r.path.includes("openid-configuration")) {
      assert.ok(
        appSrc.includes("/.well-known"),
        "/.well-known route must be mounted in app.ts"
      );
      continue;
    }

    if (r.path.startsWith("/api/admin")) {
      const subPath = r.path.replace("/api/admin", "");
      assert.ok(
        adminRoutesSrc.includes(`"${subPath}"`) || adminRoutesSrc.includes(`'${subPath}'`),
        `Admin route '${subPath}' from ${r.path} not found in admin.ts`
      );
    } else if (r.path.startsWith("/api/auth/app-admin")) {
      const subPath = r.path.replace("/api/auth/app-admin", "");
      assert.ok(
        appAdminSrc.includes(`"${subPath}"`) || appAdminSrc.includes(`'${subPath}'`),
        `App Admin route '${subPath}' from ${r.path} not found in app-admin-auth.ts`
      );
    } else if (r.path.startsWith("/api/auth")) {
      const subPath = r.path.replace("/api/auth", "");
      assert.ok(
        authRoutesSrc.includes(subPath) || authUtilSrc.includes(subPath) || authUtilSrc.includes(subPath.replace("/oauth2/", "")),
        `Auth route '${subPath}' from ${r.path} not found in auth.ts or auth.ts plugin definition`
      );
    } else {
      assert.ok(
        appSrc.includes(`"${r.path}"`) || appSrc.includes(`'${r.path}'`),
        `Root route '${r.path}' not found in app.ts`
      );
    }
  }
});

// 4. Verify Canonical Terminology Consistency in Documentation
check("Documentation contains no forbidden architectural contradictions", () => {
  const canonicalDoc = fs.readFileSync(path.join(repoRoot, "docs/SECURITY_CANONICAL.md"), "utf-8");
  assert.ok(canonicalDoc.includes("NORMATIVE / AUTHORITATIVE"), "SECURITY_CANONICAL.md must declare NORMATIVE status");

  // Verify that README references SECURITY_CANONICAL.md
  const readme = fs.readFileSync(path.join(repoRoot, "README.md"), "utf-8");
  assert.ok(
    readme.includes("SECURITY_CANONICAL.md"),
    "README.md must reference docs/SECURITY_CANONICAL.md as canonical standard"
  );

  // Verify AGENTS.md enforces the 7 non-negotiable rules
  const agentsMd = fs.readFileSync(path.join(repoRoot, "AGENTS.md"), "utf-8");
  assert.ok(
    agentsMd.includes("The 7 Non-Negotiable Agent Rules"),
    "AGENTS.md must list The 7 Non-Negotiable Agent Rules"
  );
  assert.ok(
    !agentsMd.includes("ALLOW_DEV_CLIENTS_IN_PRODUCTION=true"),
    "AGENTS.md must never suggest ALLOW_DEV_CLIENTS_IN_PRODUCTION=true globally"
  );
});

// 5. Environment Schema Consistency Check
check("Environment variables in documentation match backend schema", () => {
  const schemaSrc = fs.readFileSync(path.join(backendRoot, "src/config/schema.ts"), "utf-8");
  const requiredVars = [
    "NODE_ENV",
    "PORT",
    "MONGO_URI",
    "BETTER_AUTH_SECRET",
    "BETTER_AUTH_URL",
    "FRONTEND_URL",
    "INTERNAL_GATEWAY_SECRET",
    "TRUSTED_PROXY_CIDRS",
  ];

  for (const v of requiredVars) {
    assert.ok(
      schemaSrc.includes(v),
      `Environment schema (schema.ts) must define required environment variable '${v}'`
    );
  }
});

console.log("================================================================");
if (errors.length > 0) {
  console.error(`  CONSISTENCY CHECK FAILED: ${errors.length} error(s) found`);
  for (const err of errors) {
    console.error(`  - ${err}`);
  }
  process.exit(1);
} else {
  console.log("  ALL DOCUMENTATION & SECURITY CONSISTENCY CHECKS PASSED (0 ERRORS)");
  console.log("================================================================");
  process.exit(0);
}
