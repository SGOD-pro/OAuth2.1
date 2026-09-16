import { betterAuth } from "better-auth";
import { mongodbAdapter } from "better-auth/adapters/mongodb";
import { MongoClient } from "mongodb";
import { config } from "dotenv";

config({ path: "hono/.env" });

const client = new MongoClient(process.env.MONGO_URI);

const auth = betterAuth({
    database: mongodbAdapter(client.db(), { client }),
    emailAndPassword: { enabled: true },
});

async function run() {
    await client.connect();
    console.log("Connected");
    
    // Create user
    try {
        const user = await auth.api.signUpEmail({
            body: {
                email: "test@swyra.com",
                password: "Password123!",
                name: "Test User"
            }
        });
        console.log("First signup success:", user.user.email);
    } catch (err) {
        console.log("First signup err:", err.message);
    }

    // Try again
    try {
        const user2 = await auth.api.signUpEmail({
            body: {
                email: "test@swyra.com",
                password: "Password123!",
                name: "Test User 2"
            }
        });
        console.log("Second signup success (UNEXPECTED):", user2.user.email);
    } catch (err) {
        console.log("Second signup err (EXPECTED):", err.message);
    }
    
    await client.close();
}
run();
