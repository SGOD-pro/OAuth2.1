import { MongoClient } from "mongodb";

const uri = "mongodb+srv://testing938212:Jarvis123@cluster0.df3gouo.mongodb.net/oauthservice";
const client = new MongoClient(uri);
await client.connect();
const db = client.db();

await db.collection("oauthClient").updateOne(
  { clientId: "VyhlDhjmztsAsFphQjBsmXiSXjfpFoug" },
  { $addToSet: { allowedOrigins: "http://localhost:5175" } }
);

await db.collection("origin_cache").deleteMany({});

console.log("Updated allowedOrigins and cleared origin_cache");
await client.close();
