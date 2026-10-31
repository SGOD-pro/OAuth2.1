import "./test-env-isolation";
import { getDb, closeDb } from "../../src/db/mongo";
import { startOriginCheck, getCachedOrigin, setCachedOrigin, setRedisOutageDetectedForTesting } from "../../src/cache/origin-cache";
import { setRedisClientForTesting } from "../../src/cache/redis";
import { markSharedRedisOutage, getSharedRedisOutage } from "../../src/db/state";
import { Redis } from "@upstash/redis";

let db: any = null;

async function handleMessage(msg: any) {
  if (!msg || typeof msg !== "object") return;

  if (msg.type === "INIT") {
    db = await getDb();
    if (msg.redisUrl && msg.redisToken) {
      const redis = new Redis({
        url: msg.redisUrl,
        token: msg.redisToken,
        retry: false,
      });
      setRedisClientForTesting(redis);
    }
    if (process.send) process.send({ type: "INIT_OK" });
    return;
  }

  if (msg.type === "START_CHECK") {
    const check = await startOriginCheck(msg.origin);
    if (process.send) {
      process.send({
        type: "CHECK_STARTED",
        origin: msg.origin,
        startTime: check.startVersion ?? check.startTime,
      });
    }
    return;
  }

  if (msg.type === "COMPLETE_WRITE") {
    await setCachedOrigin(msg.origin, msg.allowed, { origin: msg.origin, startVersion: msg.startTime, startTime: msg.startTime });
    if (process.send) {
      process.send({
        type: "WRITE_COMPLETED",
        origin: msg.origin,
      });
    }
    return;
  }

  if (msg.type === "CHECK_CACHE") {
    const val = await getCachedOrigin(msg.origin);
    if (process.send) {
      process.send({
        type: "CACHE_RESULT",
        origin: msg.origin,
        value: val,
      });
    }
    return;
  }

  if (msg.type === "TRIGGER_OUTAGE") {
    if (db) {
      await markSharedRedisOutage(db, true);
    }
    setRedisOutageDetectedForTesting(true);
    if (process.send) {
      process.send({
        type: "OUTAGE_TRIGGERED",
      });
    }
    return;
  }

  if (msg.type === "EXIT") {
    await closeDb();
    process.exit(0);
  }
}

process.on("message", (msg) => {
  handleMessage(msg).catch((err) => {
    if (process.send) {
      process.send({ type: "ERROR", error: err?.message || String(err) });
    }
  });
});
