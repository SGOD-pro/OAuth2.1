import { MongoClient } from "mongodb";
import { config } from "dotenv";

config();

async function run() {
    if (!process.env.MONGO_URI) {
        console.error("MONGO_URI is missing");
        process.exit(1);
    }
    const client = new MongoClient(process.env.MONGO_URI);
    try {
        await client.connect();
        const db = client.db();
        
        console.log("Connected. Creating indexes...");
        const collection = db.collection("user_app_registrations");
        
        // Create unique compound index
        await collection.createIndex(
            { userId: 1, clientId: 1 }, 
            { unique: true, name: "user_app_unique_idx" }
        );
        
        console.log("Successfully created user_app_registrations index.");
    } catch (err) {
        console.error("Error:", err);
    } finally {
        await client.close();
    }
}

run();
