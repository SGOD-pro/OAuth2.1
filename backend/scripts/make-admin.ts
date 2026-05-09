/**
 * make-admin.ts — Promote a user to admin role.
 *
 * Usage:
 *   npx ts-node scripts/make-admin.ts your@email.com
 *
 * Better Auth MongoDB collection: 'user'
 * (confirmed: Better Auth uses 'user' as the collection name for the
 *  MongoDB adapter, matching the lowercase model name)
 */

import * as dotenv from 'dotenv';
import { MongoClient } from 'mongodb';

dotenv.config();

async function main() {
  const email = process.argv[2];
  if (!email) {
    console.error('Usage: npx ts-node scripts/make-admin.ts your@email.com');
    process.exit(1);
  }

  const mongoUri = process.env.MONGO_URI;
  if (!mongoUri) {
    console.error('MONGO_URI is not set. Check your .env file.');
    process.exit(1);
  }

  const client = new MongoClient(mongoUri);

  try {
    await client.connect();
    const db = client.db();

    const user = await db.collection('user').findOne({ email });

    if (!user) {
      console.error(`❌ User not found: ${email}`);
      console.error('   Sign up first at the auth service, then run this script.');
      process.exit(1);
    }

    if (user['role'] === 'admin') {
      console.log(`ℹ️  ${email} is already an admin.`);
      process.exit(0);
    }

    await db.collection('user').updateOne(
      { email },
      { $set: { role: 'admin' } },
    );

    console.log(`✓ ${email} is now an admin.`);
    console.log('  They can access /admin after signing in.');
  } finally {
    await client.close();
    process.exit(0);
  }
}

main().catch((err) => {
  console.error('Fatal error:', err);
  process.exit(1);
});
