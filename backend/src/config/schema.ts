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

    // Dedicated signing key for app-admin JWTs (≥32 chars).
    // Required in production. In development/test, falls back to HMAC sub-key.
    APP_ADMIN_JWT_SECRET: z.string().min(32).optional(),

    // Dedicated AES-256-GCM encryption key for app-admin TOTP secrets at rest (≥32 chars).
    // Required in production. In development/test, falls back to derived sub-key.
    APP_ADMIN_TOTP_KEY: z.string().min(32).optional(),

    // Optional internal gateway secret for protecting private management endpoints from direct external invoke
    INTERNAL_GATEWAY_SECRET: z.string().min(32).optional(),

    // In production, whether development OAuth clients with loopback URIs are permitted (defaults to false)
    ALLOW_DEV_CLIENTS_IN_PRODUCTION: z.string().default('false'),
}).superRefine((data, ctx) => {
    if (data.NODE_ENV === 'production') {
        const validateProductionUrl = (val: string, fieldName: 'BETTER_AUTH_URL' | 'FRONTEND_URL') => {
            try {
                const u = new URL(val);
                if (u.protocol !== 'https:') {
                    ctx.addIssue({
                        code: z.ZodIssueCode.custom,
                        message: `${fieldName} must use HTTPS in production`,
                        path: [fieldName],
                    });
                }
                const host = u.hostname.toLowerCase().replace(/^\[|\]$/g, '');
                if (host === 'localhost' || host === '127.0.0.1' || host === '::1' || host.endsWith('.localhost')) {
                    ctx.addIssue({
                        code: z.ZodIssueCode.custom,
                        message: `${fieldName} cannot be a loopback address in production`,
                        path: [fieldName],
                    });
                }
            } catch {
                ctx.addIssue({
                    code: z.ZodIssueCode.custom,
                    message: `${fieldName} must be a valid URL`,
                    path: [fieldName],
                });
            }
        };

        if (data.BETTER_AUTH_URL) validateProductionUrl(data.BETTER_AUTH_URL, 'BETTER_AUTH_URL');
        if (data.FRONTEND_URL) validateProductionUrl(data.FRONTEND_URL, 'FRONTEND_URL');

        if (!data.APP_ADMIN_JWT_SECRET || data.APP_ADMIN_JWT_SECRET.trim().length < 32) {
            ctx.addIssue({
                code: z.ZodIssueCode.custom,
                message: 'APP_ADMIN_JWT_SECRET is required in production and must be at least 32 characters',
                path: ['APP_ADMIN_JWT_SECRET'],
            });
        }
        if (!data.APP_ADMIN_TOTP_KEY || data.APP_ADMIN_TOTP_KEY.trim().length < 32) {
            ctx.addIssue({
                code: z.ZodIssueCode.custom,
                message: 'APP_ADMIN_TOTP_KEY is required in production and must be at least 32 characters',
                path: ['APP_ADMIN_TOTP_KEY'],
            });
        }
    }
});

export type Env = z.infer<typeof envSchema>