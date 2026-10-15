import {
  MongoClient,
  MongoClientOptions,
  Db,
} from "mongodb";

import { config } from "../config";

const mongoOptions: MongoClientOptions = {
  maxPoolSize: 10,
  minPoolSize: 1,
  serverSelectionTimeoutMS: 10000,
  socketTimeoutMS: 30000,
  maxIdleTimeMS: 60000,
};

let client = new MongoClient(config.mongo.uri, mongoOptions);
export const database: Db = new Proxy({} as Db, {
  get: (_, prop) => {
    if (testDbOverride) {
      const val = (testDbOverride as any)[prop];
      return typeof val === "function" ? val.bind(testDbOverride) : val;
    }
    const activeDb = client.db();
    const val = (activeDb as any)[prop];
    return typeof val === "function" ? val.bind(activeDb) : val;
  },
});

let db: Db | null = null;
let connectPromise: Promise<Db> | null = null;
let testDbOverride: Db | null = null;

export function setTestDbOverride(mock: Db | null): void {
  testDbOverride = mock;
}

function setupClientListeners(c: MongoClient): void {
  c.on("close", () => {
    console.warn("[MONGO] Client connection closed. Resetting connection state.");
    db = null;
    connectPromise = null;
  });
  c.on("topologyClosed", () => {
    console.warn("[MONGO] Topology closed. Resetting connection state.");
    db = null;
    connectPromise = null;
  });
}

setupClientListeners(client);

// Initiate background connection, catching error and resetting db/connectPromise so getDb can retry cleanly
connectPromise = client.connect().then(() => {
  db = client.db();
  console.log("Mongo connected");
  return db;
}).catch((err) => {
  console.warn("Background Mongo connection attempt deferred:", err?.message || err);
  db = null;
  connectPromise = null;
  return null as any;
});

function getOrInitClient(): MongoClient {
  if ((client as any).topology?.isClosed?.()) {
    try {
      client.removeAllListeners();
    } catch {}
    client = new MongoClient(config.mongo.uri, mongoOptions);
    setupClientListeners(client);
    db = null;
    connectPromise = null;
  }
  return client;
}

export async function getDb(): Promise<Db> {
  if (testDbOverride) {
    return testDbOverride;
  }
  if (db && !(client as any).topology?.isClosed?.()) {
    return db;
  }

  const activeClient = getOrInitClient();

  if (!connectPromise) {
    connectPromise = activeClient.connect().then(() => {
      db = activeClient.db();
      console.log("Mongo connected");
      return db;
    }).catch((err) => {
      db = null;
      connectPromise = null;
      throw err;
    });
  }

  const result = await connectPromise;
  if (!result) {
    connectPromise = null;
    return getDb();
  }
  return result;
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
  db = null;
  connectPromise = null;
}