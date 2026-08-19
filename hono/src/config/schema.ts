import { z } from 'zod'

export const envSchema = z.object({
    NODE_ENV: z.enum([
        'development',
        'production',
        'test',
    ]),

    PORT: z.coerce.number().default(3000),

    MONGO_URI: z.url(),

    BETTER_AUTH_SECRET: z.string().min(32),
    BETTER_AUTH_URL: z.string(),

    GOOGLE_CLIENT_ID: z.string(),
    GOOGLE_CLIENT_SECRET: z.string(),
    FRONTEND_URL: z.string(),
    TRUSTED_PROXY_CIDRS: z.string().default(''),
    AUTH_PUBLIC_SIGNUP_ENABLED: z.string().default('true'),
    AUTH_EMAIL_VERIFICATION_ENABLED: z.string().default('false'),

    VITE_CLIENT_ID: z.string().optional(),
    PUBLIC_KEY: z.string().optional(),

    UPSTASH_REDIS_REST_URL: z.string().optional(),
    UPSTASH_REDIS_REST_TOKEN: z.string().optional(),
    REDIS_URL: z.string().optional(),
    REDIS_TOKEN: z.string().optional(),
})

export type Env = z.infer<typeof envSchema>