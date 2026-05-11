import {
  MongoClient,
  Db,
} from "mongodb";

import { config }
  from "../config";

const client =
  new MongoClient(
    config.mongo.uri
  );

let db: Db;

let connectPromise:
  Promise<Db> | null = null;

export async function connectDb() {
  if (db) {
    return db;
  }

  if (!connectPromise) {
    connectPromise =
      client
        .connect()
        .then(() => {
          db = client.db();

          console.log(
            "Mongo connected"
          );

          return db;
        });
  }

  return connectPromise;
}

export {
  client,
  db,
};