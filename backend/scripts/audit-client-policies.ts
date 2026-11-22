#!/usr/bin/env tsx
/**
 * Read-Only OAuth Client Policy Audit CLI (Slice P1a)
 *
 * Scans MongoDB oauthClient records, executes resolveClientPolicy,
 * and reports clean and ambiguous records without performing any database writes.
 *
 * Usage:
 *   npx tsx scripts/audit-client-policies.ts [--json]
 */

import { MongoClient, Db } from "mongodb";
import dotenv from "dotenv";
import { auditClientPolicies, ClientAuditSummary } from "../src/identity/client-policy";

dotenv.config({ path: ".env" });

function printHumanReport(summary: ClientAuditSummary): void {
  console.log("================================================================");
  console.log("  SWYRA AUTH -- READ-ONLY OAUTH CLIENT POLICY AUDIT (P1a)");
  console.log("================================================================");
  console.log(`Timestamp: ${summary.timestamp}`);
  console.log(`Total Clients Inspected: ${summary.totalClients}`);
  console.log("");
  console.log("CLASSIFICATION BREAKDOWN:");
  console.log(`  Explicitly Migrated (V2):        ${summary.migratedCount}`);
  console.log(`  Compatible Open Public:          ${summary.compatibleOpenPublicCount}`);
  console.log(`  Compatible Private Confidential: ${summary.compatiblePrivateConfidentialCount}`);
  console.log(`  Compatible Open Confidential:    ${summary.compatibleOpenConfidentialCount}`);
  console.log(`  Compatible Private Public:       ${summary.compatiblePrivatePublicCount}`);
  console.log(`  Ambiguous / Conflicting:         ${summary.ambiguousCount}`);
  console.log("----------------------------------------------------------------");

  if (summary.ambiguousCount > 0) {
    console.log("AMBIGUOUS RECORDS REQUIRING ADMINISTRATIVE REVIEW:");
    for (const client of summary.clients) {
      if (client.isAmbiguous) {
        console.log(`  - Client ID: ${client.clientId} (ID: ${client.id})`);
        console.log(`    Name:        ${client.name}`);
        console.log(`    ReasonCodes: ${client.reasonCodes.join(", ")}`);
        console.log(`    Details:     ${client.reasons.join("; ")}`);
      }
    }
    console.log("----------------------------------------------------------------");
    console.log("RESULT: Ambiguous records found. Operators must assign explicit");
    console.log("        clientType and accessPolicy before activating open access.");
  } else {
    console.log("RESULT: Clean audit. Zero ambiguous client records detected.");
  }
  console.log("================================================================");
}

export async function runClientPolicyAudit(options?: { dbUri?: string; dbName?: string }): Promise<number> {
  const isJson = process.argv.includes("--json");
  const uri = options?.dbUri || process.env.MONGO_URI;

  if (!uri) {
    const msg = "MONGO_URI environment variable is required to execute client policy audit.";
    if (isJson) {
      console.error(JSON.stringify({ error: "ConfigurationError", message: msg }));
    } else {
      console.error(`[AUDIT_ERROR] ${msg}`);
    }
    return 1;
  }

  const client = new MongoClient(uri);

  try {
    await client.connect();
    const db: Db = client.db(options?.dbName);
    const summary = await auditClientPolicies(db);

    if (isJson) {
      console.log(JSON.stringify(summary, null, 2));
    } else {
      printHumanReport(summary);
    }

    return summary.ambiguousCount === 0 ? 0 : 1;
  } catch (err: any) {
    if (isJson) {
      console.error(JSON.stringify({ error: "AuditFailed", message: err?.message || String(err) }));
    } else {
      console.error("[AUDIT_ERROR] Failed to execute client policy audit:", err?.message || err);
    }
    return 1;
  } finally {
    await client.close().catch(() => {});
  }
}

// Execute standalone when invoked directly
if (process.argv[1]?.endsWith("audit-client-policies.ts")) {
  runClientPolicyAudit()
    .then((code) => {
      process.exit(code);
    })
    .catch(() => {
      process.exit(1);
    });
}
