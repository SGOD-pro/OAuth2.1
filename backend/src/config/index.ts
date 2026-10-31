import { getEnv } from './env'
import { createHmac } from 'crypto'

const parsedEnv = getEnv()

export const config = {
    get env() {
        return process.env.NODE_ENV || parsedEnv.NODE_ENV
    },

    get port() {
        return Number(process.env.PORT) || parsedEnv.PORT
    },

    mongo: {
        get uri() {
            return process.env.MONGO_URI || parsedEnv.MONGO_URI
        },
    },

    redis: {
        get url() {
            if (process.env.NODE_ENV === "test" && !process.env.ALLOW_TEST_REDIS) {
                return process.env.TEST_REDIS_URL || undefined;
            }
            return (
                process.env.UPSTASH_REDIS_REST_URL ||
                process.env.REDIS_URL ||
                (process.env.NODE_ENV !== "test" ? parsedEnv.UPSTASH_REDIS_REST_URL || parsedEnv.REDIS_URL : undefined)
            );
        },
        get token() {
            if (process.env.NODE_ENV === "test" && !process.env.ALLOW_TEST_REDIS) {
                return process.env.TEST_REDIS_TOKEN || undefined;
            }
            return (
                process.env.UPSTASH_REDIS_REST_TOKEN ||
                process.env.UPSTASH_REDIS_API_KEY ||
                process.env.REDIS_TOKEN ||
                (process.env.NODE_ENV !== "test"
                    ? parsedEnv.UPSTASH_REDIS_REST_TOKEN || (parsedEnv as any).UPSTASH_REDIS_API_KEY || parsedEnv.REDIS_TOKEN
                    : undefined)
            );
        },
        get enabled(): boolean {
            return Boolean(this.url && this.token)
        },
    },

    auth: {
        get secret() {
            return process.env.BETTER_AUTH_SECRET || parsedEnv.BETTER_AUTH_SECRET
        },
        get baseURL() {
            return process.env.BETTER_AUTH_URL || parsedEnv.BETTER_AUTH_URL
        },
        get publicSignupEnabled() {
            return (process.env.AUTH_PUBLIC_SIGNUP_ENABLED || parsedEnv.AUTH_PUBLIC_SIGNUP_ENABLED) === 'true'
        },
        get emailVerificationEnabled() {
            return (process.env.AUTH_EMAIL_VERIFICATION_ENABLED || parsedEnv.AUTH_EMAIL_VERIFICATION_ENABLED) === 'true'
        },
    },

    get betterAuthSecret() {
        return this.auth.secret
    },

    google: {
        get clientId() {
            return process.env.GOOGLE_CLIENT_ID || parsedEnv.GOOGLE_CLIENT_ID
        },
        get clientSecret() {
            return process.env.GOOGLE_CLIENT_SECRET || parsedEnv.GOOGLE_CLIENT_SECRET
        },
    },

    get frontendUrl() {
        return process.env.FRONTEND_URL || parsedEnv.FRONTEND_URL
    },

    app: {
        get clientId() {
            return process.env.VITE_CLIENT_ID || parsedEnv.VITE_CLIENT_ID
        },
        get publicKey() {
            return process.env.PUBLIC_KEY || parsedEnv.PUBLIC_KEY
        },
    },

    get trustedProxyCidrs() {
        const raw = process.env.TRUSTED_PROXY_CIDRS ?? parsedEnv.TRUSTED_PROXY_CIDRS ?? ''
        return raw
            .split(',')
            .map((value) => value.trim())
            .filter(Boolean)
    },

    get internalGatewaySecret(): string | undefined {
        const secret = process.env.INTERNAL_GATEWAY_SECRET !== undefined
            ? process.env.INTERNAL_GATEWAY_SECRET
            : parsedEnv.INTERNAL_GATEWAY_SECRET
        if (this.env === 'production' && (!secret || secret.trim().length < 32)) {
            const reason = !secret
                ? 'Missing or empty INTERNAL_GATEWAY_SECRET'
                : `INTERNAL_GATEWAY_SECRET length (${secret.trim().length}) is under required minimum of 32 characters`
            console.error(`[CONFIG_ERROR] ${reason}. Production deployments require a 32+ character internal gateway secret.`)
            throw new Error('INTERNAL_GATEWAY_SECRET must be explicitly configured in production (minimum 32 characters)')
        }
        return secret
    },

    get allowDevClientsInProduction(): boolean {
        const val = process.env.ALLOW_DEV_CLIENTS_IN_PRODUCTION ?? parsedEnv.ALLOW_DEV_CLIENTS_IN_PRODUCTION ?? 'false'
        return val === 'true'
    },
}
