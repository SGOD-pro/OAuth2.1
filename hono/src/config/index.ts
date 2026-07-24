import { getEnv } from './env'

const parsedEnv = getEnv()

export const config = Object.freeze({
    env: parsedEnv.NODE_ENV,

    port: parsedEnv.PORT,

    mongo: {
        uri: parsedEnv.MONGO_URI,
    },

    auth: {
        secret: parsedEnv.BETTER_AUTH_SECRET,
        baseURL: parsedEnv.BETTER_AUTH_URL,
        publicSignupEnabled:
            parsedEnv.AUTH_PUBLIC_SIGNUP_ENABLED === 'true',
        emailVerificationEnabled:
            parsedEnv.AUTH_EMAIL_VERIFICATION_ENABLED === 'true',
    },

    google: {
        clientId:
            parsedEnv.GOOGLE_CLIENT_ID,

        clientSecret:
            parsedEnv.GOOGLE_CLIENT_SECRET,
    },

    frontendUrl: parsedEnv.FRONTEND_URL,

    dynamodb: {
        table: parsedEnv.DYNAMODB_TABLE,
        region: parsedEnv.AWS_REGION,
    },

    trustedProxyCidrs:
        parsedEnv.TRUSTED_PROXY_CIDRS
            .split(',')
            .map((value) => value.trim())
            .filter(Boolean),
})
