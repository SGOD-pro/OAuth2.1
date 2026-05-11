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
    },

    google: {
        clientId:
            parsedEnv.GOOGLE_CLIENT_ID,

        clientSecret:
            parsedEnv.GOOGLE_CLIENT_SECRET,
    },

    frontendUrl: parsedEnv.FRONTEND_URL,
})