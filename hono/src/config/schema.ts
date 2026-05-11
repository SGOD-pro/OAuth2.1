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
})

export type Env = z.infer<typeof envSchema>