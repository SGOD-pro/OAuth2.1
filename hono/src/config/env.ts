import 'dotenv/config'

import { env } from 'hono/adapter'
import type { Context } from 'hono'

import { envSchema } from './schema'

export function getEnv(c?: Context) {
  const runtimeEnv = c
    ? env(c)
    : process.env as Record<string, string>

  return envSchema.parse(runtimeEnv)
}