import { execSync } from "node:child_process";
import crypto from "node:crypto";
import { MongoClient } from "mongodb";

export const CONTAINER_NAME = "swyra-auth-test-mongo";
export const HARNESS_LABEL = "swyra-auth-test-harness=true";
export const DOCKER_IMAGE = "mongodb/mongodb-community-server:8.0-ubi8-slim";
export const DEFAULT_HOST_PORT = 27018;
export const ADMIN_USER = "testAdmin";
export const ADMIN_PASS = "testAdminPassword123";
export const WIREDTIGER_CACHE_GB = "0.25";
export const CONTAINER_MEM_LIMIT = "1536m";

export function getHarnessPort(): number {
  const envPort = process.env.TEST_MONGO_PORT;
  if (envPort) {
    const parsed = parseInt(envPort, 10);
    if (!isNaN(parsed) && parsed > 0 && parsed <= 65535) return parsed;
  }
  return DEFAULT_HOST_PORT;
}

export function getBaseAdminUri(port = getHarnessPort()): string {
  return `mongodb://${ADMIN_USER}:${ADMIN_PASS}@127.0.0.1:${port}/?authSource=admin&directConnection=true`;
}

export function getSuiteUri(dbName: string, port = getHarnessPort()): string {
  return `mongodb://${ADMIN_USER}:${ADMIN_PASS}@127.0.0.1:${port}/${dbName}?authSource=admin&directConnection=true`;
}

export function isDockerContainerRunning(): boolean {
  try {
    const running = execSync(
      `docker ps --filter "name=^/${CONTAINER_NAME}$" --filter "status=running" --format "{{.ID}}"`,
      { encoding: "utf8" }
    ).trim();
    return !!running;
  } catch {
    return false;
  }
}

export async function isHarnessRunning(port = getHarnessPort()): Promise<boolean> {
  const uri = getBaseAdminUri(port);
  let client: MongoClient | null = null;
  try {
    client = new MongoClient(uri, { serverSelectionTimeoutMS: 1500 });
    await client.connect();
    const adminDb = client.db("admin");
    const marker = await adminDb.collection("swyra_harness_meta").findOne({ _id: "marker" as any });
    return marker?.label === "swyra-auth-test-harness";
  } catch {
    return false;
  } finally {
    if (client) await client.close().catch(() => {});
  }
}

export async function startSharedMongo(): Promise<{ port: number; uri: string }> {
  const port = getHarnessPort();

  if (await isHarnessRunning(port)) {
    return { port, uri: getSuiteUri("test", port) };
  }

  // Remove stale or dead container with the same name if owned by harness
  try {
    const isOwned = execSync(
      `docker ps -a --filter "name=^/${CONTAINER_NAME}$" --filter "label=${HARNESS_LABEL}" --format "{{.ID}}"`,
      { encoding: "utf8" }
    ).trim();
    if (isOwned) {
      execSync(`docker rm -f ${CONTAINER_NAME}`, { stdio: "ignore" });
    }
  } catch {}

  const rawScript = [
    "set -e",
    "head -c 60 /dev/urandom | base64 > /tmp/keyfile && chmod 400 /tmp/keyfile",
    `mongod --fork --logpath /tmp/init.log --dbpath /data/db --wiredTigerCacheSizeGB ${WIREDTIGER_CACHE_GB}`,
    `mongosh --eval 'db.getSiblingDB("admin").createUser({ user: "${ADMIN_USER}", pwd: "${ADMIN_PASS}", roles: ["root"] })'`,
    "mongod --shutdown --dbpath /data/db",
    `mongod --fork --logpath /tmp/rs.log --dbpath /data/db --replSet rs0 --keyFile /tmp/keyfile --bind_ip_all --wiredTigerCacheSizeGB ${WIREDTIGER_CACHE_GB}`,
    `mongosh -u ${ADMIN_USER} -p ${ADMIN_PASS} --authenticationDatabase admin --eval 'rs.initiate({ _id: "rs0", members: [{ _id: 0, host: "127.0.0.1:27017" }] })'`,
    `mongosh -u ${ADMIN_USER} -p ${ADMIN_PASS} --authenticationDatabase admin --eval 'while (rs.status().members[0].stateStr !== "PRIMARY") { sleep(200); }'`,
    "echo BOOTSTRAP_COMPLETE",
    "tail -f /tmp/rs.log",
  ].join("\n");

  const b64 = Buffer.from(rawScript).toString("base64");

  const dockerCmd = [
    "run -d",
    `--name ${CONTAINER_NAME}`,
    `--label ${HARNESS_LABEL}`,
    `--memory ${CONTAINER_MEM_LIMIT}`,
    `--ulimit nofile=65536:65536`,
    `--tmpfs /data/db:rw,uid=1000,gid=1000,mode=0700`,
    `-p 127.0.0.1:${port}:27017`,
    DOCKER_IMAGE,
    `bash -c "echo '${b64}' | base64 -d | bash"`,
  ].join(" ");

  execSync(`docker ${dockerCmd}`, { stdio: ["pipe", "pipe", "inherit"] });

  // Wait for replica set PRIMARY readiness
  const adminUri = getBaseAdminUri(port);
  let ready = false;
  let client: MongoClient | null = null;

  for (let attempt = 0; attempt < 50; attempt++) {
    await new Promise((resolve) => setTimeout(resolve, 500));
    try {
      if (!client) {
        client = new MongoClient(adminUri, { serverSelectionTimeoutMS: 1500 });
        await client.connect();
      }
      const adminDb = client.db("admin");
      const hello = await adminDb.command({ hello: 1 });
      if (hello.isWritablePrimary) {
        ready = true;
        await adminDb.collection("swyra_harness_meta").updateOne(
          { _id: "marker" as any },
          { $set: { label: "swyra-auth-test-harness", startedAt: new Date() } },
          { upsert: true }
        );
        break;
      }
    } catch {
      if (client) {
        await client.close().catch(() => {});
        client = null;
      }
    }
  }

  if (client) await client.close().catch(() => {});

  if (!ready) {
    try {
      const logs = execSync(`docker logs --tail 40 ${CONTAINER_NAME}`, { encoding: "utf8" });
      console.error(`Container failed to reach PRIMARY. Logs:\n${logs}`);
    } catch {}
    throw new Error(`[TEST_HARNESS] Shared Docker MongoDB failed to become ready on 127.0.0.1:${port}`);
  }

  return { port, uri: getSuiteUri("test", port) };
}

export function stopSharedMongo(): void {
  try {
    const isOwned = execSync(
      `docker ps -a --filter "name=^/${CONTAINER_NAME}$" --filter "label=${HARNESS_LABEL}" --format "{{.ID}}"`,
      { encoding: "utf8" }
    ).trim();
    if (isOwned) {
      execSync(`docker rm -f ${CONTAINER_NAME}`, { stdio: "ignore" });
    }
  } catch {}
}

export interface SuiteDatabaseContext {
  dbName: string;
  uri: string;
  client: MongoClient;
  cleanup: () => Promise<void>;
}

export async function setupSuiteDatabase(suiteName: string): Promise<SuiteDatabaseContext> {
  process.env.NODE_ENV = "test";
  const port = getHarnessPort();
  const expectedPrefix = `mongodb://${ADMIN_USER}:${ADMIN_PASS}@127.0.0.1:${port}/`;

  if (process.env.MONGO_URI && process.env.MONGO_URI.startsWith(expectedPrefix)) {
    const uri = process.env.MONGO_URI;
    const parsed = new URL(uri);
    const dbName = parsed.pathname.replace(/^\//, "") || `test_${suiteName}`;
    const client = new MongoClient(uri);
    await client.connect();
    const cleanup = async () => {
      try {
        await client.db(dbName).dropDatabase();
      } catch {}
      try {
        await client.close();
      } catch {}
    };
    return { dbName, uri, client, cleanup };
  }

  const { port: actualPort } = await startSharedMongo();
  const cleanName = suiteName.toLowerCase().replace(/[^a-z0-9_]/g, "_").slice(0, 30);
  const dbName = `test_${cleanName}_${crypto.randomBytes(4).toString("hex")}`;
  const uri = getSuiteUri(dbName, actualPort);

  process.env.MONGO_URI = uri;

  const client = new MongoClient(uri);
  await client.connect();

  const cleanup = async () => {
    try {
      const db = client.db(dbName);
      await db.dropDatabase();
    } catch {}
    try {
      await client.close();
    } catch {}
  };

  return { dbName, uri, client, cleanup };
}
