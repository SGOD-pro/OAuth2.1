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
    AUTH_EMAIL_VERIFICATION_ROLLOUT_MODE: z.enum(['enforce_new', 'enforce_all']).optional(),
    AUTH_EMAIL_VERIFICATION_ENFORCED_AFTER: z.string().optional(),
    EMAIL_DELIVERY_WEBHOOK_URL: z.string().optional(),

    VITE_CLIENT_ID: z.string().optional(),
    PUBLIC_KEY: z.string().optional(),

    UPSTASH_REDIS_REST_URL: z.string().optional(),
    UPSTASH_REDIS_REST_TOKEN: z.string().optional(),
    UPSTASH_REDIS_API_KEY: z.string().optional(),
    REDIS_URL: z.string().optional(),
    REDIS_TOKEN: z.string().optional(),

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

        if (!data.INTERNAL_GATEWAY_SECRET || data.INTERNAL_GATEWAY_SECRET.trim().length < 32) {
            ctx.addIssue({
                code: z.ZodIssueCode.custom,
                message: 'INTERNAL_GATEWAY_SECRET is required in production and must be at least 32 characters',
                path: ['INTERNAL_GATEWAY_SECRET'],
            });
        }
    }

    if (data.AUTH_EMAIL_VERIFICATION_ENABLED === 'true') {
        if (!data.EMAIL_DELIVERY_WEBHOOK_URL || data.EMAIL_DELIVERY_WEBHOOK_URL.trim().length === 0) {
            ctx.addIssue({
                code: z.ZodIssueCode.custom,
                message: 'EMAIL_DELIVERY_WEBHOOK_URL is required when AUTH_EMAIL_VERIFICATION_ENABLED is true',
                path: ['EMAIL_DELIVERY_WEBHOOK_URL'],
            });
        } else {
            try {
                const u = new URL(data.EMAIL_DELIVERY_WEBHOOK_URL);
                if (data.NODE_ENV === 'production') {
                    if (u.protocol !== 'https:') {
                        ctx.addIssue({
                            code: z.ZodIssueCode.custom,
                            message: 'EMAIL_DELIVERY_WEBHOOK_URL must use HTTPS in production',
                            path: ['EMAIL_DELIVERY_WEBHOOK_URL'],
                        });
                    }
                    const host = u.hostname.toLowerCase().replace(/^\[|\]$/g, '');
                    if (host === 'localhost' || host === '127.0.0.1' || host === '::1' || host.endsWith('.localhost')) {
                        ctx.addIssue({
                            code: z.ZodIssueCode.custom,
                            message: 'EMAIL_DELIVERY_WEBHOOK_URL cannot be a loopback address in production',
                            path: ['EMAIL_DELIVERY_WEBHOOK_URL'],
                        });
                    }
                }
            } catch {
                ctx.addIssue({
                    code: z.ZodIssueCode.custom,
                    message: 'EMAIL_DELIVERY_WEBHOOK_URL must be a valid URL',
                    path: ['EMAIL_DELIVERY_WEBHOOK_URL'],
                });
            }
        }
    }
});

export type Env = z.infer<typeof envSchema>