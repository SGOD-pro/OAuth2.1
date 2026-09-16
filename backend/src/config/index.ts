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
            return process.env.UPSTASH_REDIS_REST_URL || process.env.REDIS_URL || parsedEnv.UPSTASH_REDIS_REST_URL || parsedEnv.REDIS_URL
        },
        get token() {
            return process.env.UPSTASH_REDIS_REST_TOKEN || process.env.REDIS_TOKEN || parsedEnv.UPSTASH_REDIS_REST_TOKEN || parsedEnv.REDIS_TOKEN
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

    /**
     * Dedicated signing key for app-admin JWTs.
     * Prefer an explicit APP_ADMIN_JWT_SECRET env var (≥32 chars).
     * If absent, derive a cryptographically independent sub-key via HMAC-SHA256
     * so the app-admin signing key is NEVER equal to the raw BETTER_AUTH_SECRET
     * used by Better Auth sessions.
     */
    get appAdminJwtSecret(): string {
        const explicit = process.env.APP_ADMIN_JWT_SECRET
        if (explicit && explicit.length >= 32) return explicit

        const masterSecret = this.auth.secret
        if (!masterSecret) throw new Error('BETTER_AUTH_SECRET is not configured')

        return createHmac('sha256', masterSecret)
            .update('app-admin-jwt-signing-v1')
            .digest('hex')
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
}
