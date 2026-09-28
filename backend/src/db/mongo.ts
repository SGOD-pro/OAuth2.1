import {
  MongoClient,
  Db,
} from "mongodb";

import { config }
  from "../config";

const client = new MongoClient(config.mongo.uri);
export const database = client.db();

let db: Db | null = null;
let connectPromise: Promise<Db> | null = null;

// Initiate connection in background, catching initial errors to prevent unhandled rejection crashing the process
connectPromise = client.connect().then(() => {
  db = database;
  console.log("Mongo connected");
  return db;
}).catch((err) => {
  console.warn("Background Mongo connection attempt deferred:", err?.message || err);
  connectPromise = null;
  return database;
});

export async function getDb(): Promise<Db> {
  if (db) {
    return db;
  }

  if (!connectPromise) {
    connectPromise = client.connect().then(() => {
      db = database;
      console.log("Mongo connected");
      return db;
    }).catch((err) => {
      connectPromise = null;
      throw err;
    });
  }

  return connectPromise;
}

export { client };

process.on("SIGTERM", async () => {
  console.log("SIGTERM: closing MongoDB connection...");
  try {
    await client.close();
  } catch {}
  process.exit(0);
});

process.on("SIGINT", async () => {
  try {
    await client.close();
  } catch {}
  process.exit(0);
});

export async function closeDb(): Promise<void> {
  try {
    await client.close();
  } catch {}
}