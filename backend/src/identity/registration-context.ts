import { AsyncLocalStorage } from "node:async_hooks";

const verifiedCreationStorage = new AsyncLocalStorage<boolean>();

/** Marks an internal async scope as backed by a consumed verified-email proof transaction. */
export function runWithVerifiedCreation<T>(work: () => Promise<T>): Promise<T> {
  return verifiedCreationStorage.run(true, work);
}

/** Returns true only while executing inside an authorized verified-proof registration transaction. */
export function isVerifiedCreationActive(): boolean {
  return verifiedCreationStorage.getStore() === true;
}
