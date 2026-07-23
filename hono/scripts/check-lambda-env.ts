/**
 * Verification script: confirms hono/src/lambda.ts uses hono/aws-lambda (not lambda-edge)
 * and that no process.env reads exist outside the composition root.
 *
 * Run: npx tsx scripts/check-lambda-env.ts
 */
import { readFileSync, readdirSync, statSync } from "node:fs";
import { resolve, join } from "node:path";

const lambdaPath = resolve(import.meta.dirname, "../src/lambda.ts");
const source = readFileSync(lambdaPath, "utf-8");

// Check 1: must import from hono/aws-lambda
if (source.includes("hono/lambda-edge")) {
  console.error("FAIL: lambda.ts still imports from hono/lambda-edge");
  process.exit(1);
}

if (!source.includes("hono/aws-lambda")) {
  console.error("FAIL: lambda.ts does not import from hono/aws-lambda");
  process.exit(1);
}

console.log("PASS: lambda.ts imports hono/aws-lambda correctly");

// Check 2: no process.env reads outside config/env.ts
const srcDir = resolve(import.meta.dirname, "../src");
const violations: string[] = [];

function walkTs(dir: string) {
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) {
      walkTs(full);
    } else if (full.endsWith(".ts")) {
      const rel = full.replace(srcDir, "src");
      if (rel.includes("config/env.ts") || rel.includes("config\\env.ts")) continue;
      const content = readFileSync(full, "utf-8");
      const lines = content.split("\n");
      for (let i = 0; i < lines.length; i++) {
        if (lines[i].includes("process.env")) {
          violations.push(`${rel}:${i + 1}: ${lines[i].trim()}`);
        }
      }
    }
  }
}

walkTs(srcDir);

if (violations.length > 0) {
  console.error("FAIL: process.env used outside composition root:");
  for (const v of violations) console.error("  " + v);
  process.exit(1);
}

console.log("PASS: no process.env reads outside config/env.ts");
