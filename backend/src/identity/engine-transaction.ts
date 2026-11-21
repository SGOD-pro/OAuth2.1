import { getCurrentAdapter, runWithTransaction } from "@better-auth/core/context";
import { mongodbAdapter } from "better-auth/adapters/mongodb";
import type { Auth, BetterAuthOptions } from "better-auth";
import type { DBTransactionAdapter } from "@better-auth/core/db/adapter";
import type { Db, MongoClient } from "mongodb";

type Work<Options extends BetterAuthOptions> = {
  adapter: DBTransactionAdapter<Options>;
  internalAdapter: Awaited<Auth<Options>["$context"]>["internalAdapter"];
};

/** P0 compatibility boundary. Not mounted on public registration routes. */
export function createEngineTransactionBoundary(db: Db, client: MongoClient) {
  const database = mongodbAdapter(db, { client, transaction: true });

  async function run<Options extends BetterAuthOptions, T>(
    engine: Auth<Options>, work: (scope: Work<Options>) => Promise<T>,
  ): Promise<T> {
    const context = await engine.$context;
    // Better Auth silently runs sequentially when transactions are disabled.
    // Require the exact transaction-enabled factory owned by this boundary.
    if (context.options.database !== database ||
        !context.adapter.options?.adapterConfig.transaction) {
      throw new Error("A transaction-enabled engine from this boundary is required");
    }
    if (await getCurrentAdapter(context.adapter) !== context.adapter) {
      throw new Error("Nested engine transactions are not supported");
    }
    return runWithTransaction(context.adapter, async () => work({
      adapter: await getCurrentAdapter(context.adapter),
      internalAdapter: context.internalAdapter,
    }));
  }

  return { database, run };
}
