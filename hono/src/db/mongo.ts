import {
  MongoClient,
  Db,
} from "mongodb";

import { config }
  from "../config";

const client = new MongoClient(config.mongo.uri);

let db: Db | null = null;

const connectPromise: Promise<Db> = client.connect().then(() => {
  db = client.db();
  console.log("Mongo connected");
  return db;
});

export async function getDb(): Promise<Db> {
  if (db) {
    return db;
  }

  return connectPromise;
}

export { client };

process.on("SIGTERM", async () => {
  console.log("SIGTERM: closing MongoDB connection...");
  await client.close();
  process.exit(0);
});

process.on("SIGINT", async () => {
  await client.close();
  process.exit(0);
});

export async function closeDb(): Promise<void> {
  await client.close();
}