import { getEnv } from '../src/config/env';
import { database, client } from '../src/db/mongo';
import { generateId } from 'better-auth';
import crypto from 'crypto';

async function registerClient() {
    try {
        await client.connect();
        
        // Use the values from your nextjs app .env file
        const clientId = process.argv[2] || "nextjs-client-id";
        const clientSecret = process.argv[3] || crypto.randomBytes(32).toString('hex');
        
        const newClient = {
            id: clientId, // better-auth typically uses the provided ID or generates one
            name: "Next.js OAuth Consumer",
            secret: clientSecret,
            redirectUris: [
                "http://localhost:3001/api/auth/callback",
                // Add any other production redirect URIs here
            ],
            grantTypes: ["authorization_code", "refresh_token"],
            responseTypes: ["code"],
            scopes: ["openid", "profile", "email", "offline_access"],
            isDev: true,
            createdAt: new Date(),
            updatedAt: new Date()
        };

        const db = database;
        const collection = db.collection('client');
        
        // Check if exists
        const existing = await collection.findOne({ id: clientId });
        if (existing) {
            console.log("Client already exists. Updating...");
            await collection.updateOne({ id: clientId }, { $set: newClient });
        } else {
            await collection.insertOne(newClient);
            console.log("Client registered successfully!");
        }

        console.log("\n--- Client Credentials ---");
        console.log(`CLIENT_ID: ${clientId}`);
        console.log(`CLIENT_SECRET: ${clientSecret}`);
        console.log("--------------------------");
        console.log("Make sure these match your Next.js .env.local file!");

    } catch (e) {
        console.error("Failed to register client:", e);
    } finally {
        await client.close();
    }
}

registerClient();
