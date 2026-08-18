import { MongoClient } from "mongodb";
import { config } from "dotenv";
config({ path: "hono/.env" });

async function run() {
    const client = new MongoClient(process.env.MONGO_URI);
    await client.connect();
    const db = client.db();
    
    const users = await db.collection("user").find({}).toArray();
    console.log("Total users:", users.length);
    
    const emails = users.map(u => u.email);
    console.log("Emails:", emails);
    
    const duplicates = emails.filter((item, index) => emails.indexOf(item) !== index);
    if (duplicates.length > 0) {
        console.log("DUPLICATES FOUND:", duplicates);
    } else {
        console.log("No duplicate emails.");
    }
    
    // Check indexes
    const indexes = await db.collection("user").indexes();
    console.log("Indexes on user collection:", indexes);
    
    await client.close();
}
run();
