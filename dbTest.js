require('dotenv').config();
const { MongoClient } = require('mongodb');

async function testConnection() {
    try {
        const client = new MongoClient(process.env.MONGODB_URI);
        await client.connect();
        console.log("✅ Connected to MongoDB successfully!");
        const db = client.db("assignment1");
        console.log("✅ Database name:", db.databaseName);
        await client.close();
    } catch (error) {
        console.error("❌ Connection failed:", error);
    }
}

testConnection();
