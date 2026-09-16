/**
 * Better Auth CLI entry point.
 * Usage: npx @better-auth/cli migrate
 *
 * This file exists ONLY for the CLI. The runtime config lives in src/utils/auth.ts.
 */
export { authProvider as auth } from "./src/utils/auth";
