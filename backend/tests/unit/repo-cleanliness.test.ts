import fs from "fs";
import path from "path";
import assert from "assert/strict";

console.log("================================================================");
console.log("  SWYRA AUTH -- REPO CLEANLINESS & MINIMALISM INVARIANT TEST");
console.log("================================================================");

const repoRoot = path.resolve(import.meta.dirname, "../../..");
const backendRoot = path.resolve(repoRoot, "backend");
const frontendRoot = path.resolve(repoRoot, "frontend");

// 1. Select component must use internal @/lib/utils and not external cn package
const selectPath = path.join(frontendRoot, "components/ui/select.tsx");
if (fs.existsSync(selectPath)) {
  const selectContent = fs.readFileSync(selectPath, "utf-8");
  assert.ok(
    !selectContent.includes('from "cn"'),
    'select.tsx must not import from external package "cn"'
  );
  assert.ok(
    selectContent.includes('from "@/lib/utils"'),
    'select.tsx must import cn from "@/lib/utils"'
  );
}

// 2. Frontend package.json must not have dead or duplicate dependencies
const fePkgPath = path.join(frontendRoot, "package.json");
const fePkg = JSON.parse(fs.readFileSync(fePkgPath, "utf-8"));
const bannedDeps = [
  "cn",
  "@fontsource-variable/space-grotesk",
  "@hugeicons/core-free-icons",
  "@hugeicons/react",
];
for (const dep of bannedDeps) {
  assert.equal(
    fePkg.dependencies?.[dep],
    undefined,
    `frontend/package.json must not contain banned dependency "${dep}"`
  );
}

// 3. Dead backend files must not exist in active trees
const bannedBackendFiles = [
  "src/utils/totp.ts",
  "src/netlify.ts",
  "check_users.mjs",
  "test_signup.mjs",
];
for (const file of bannedBackendFiles) {
  const fullPath = path.join(backendRoot, file);
  assert.ok(
    !fs.existsSync(fullPath),
    `Dead backend file must be removed: ${file}`
  );
}

// 4. Dead frontend UI components must not exist
const bannedFrontendFiles = [
  "components/ui/alert.tsx",
  "components/ui/breadcrumb.tsx",
  "components/ui/popover.tsx",
];
for (const file of bannedFrontendFiles) {
  const fullPath = path.join(frontendRoot, file);
  assert.ok(
    !fs.existsSync(fullPath),
    `Unused frontend component must be removed: ${file}`
  );
}

// 5. Hugeicons must not be imported in any UI component
const uiDir = path.join(frontendRoot, "components/ui");
if (fs.existsSync(uiDir)) {
  const files = fs.readdirSync(uiDir);
  for (const f of files) {
    if (f.endsWith(".tsx") || f.endsWith(".ts")) {
      const code = fs.readFileSync(path.join(uiDir, f), "utf-8");
      assert.ok(
        !code.includes("@hugeicons"),
        `Component ${f} must not import from @hugeicons; use lucide-react instead`
      );
    }
  }
}

// 6. Auth routes must not export dead bypass helper
const authRoutePath = path.join(backendRoot, "src/routes/auth.ts");
const authRouteCode = fs.readFileSync(authRoutePath, "utf-8");
assert.ok(
  !authRouteCode.includes("hasAppAccessBypass"),
  "auth.ts must not contain dead function hasAppAccessBypass"
);

// 7. Root must not contain legacy scratchpad docs
const bannedRootDocs = [
  "AGENT.md",
  "prompt.md",
  "boundaries.md",
  "projectrequirement.md",
  "FIX.MD",
  "ISSUES.md",
];
for (const doc of bannedRootDocs) {
  const fullPath = path.join(repoRoot, doc);
  assert.ok(
    !fs.existsSync(fullPath),
    `Legacy scratchpad document must be archived: ${doc}`
  );
}

console.log("[PASS] All repository cleanliness and lean invariants verified!");
process.exit(0);
