import { Hono } from 'hono'
import { connectDb } from "./db/mongo";
await connectDb();

import admin from './routes/admin'
import auth from './routes/auth'
import { dynamicCors } from './middleware/cors';
import {requireAdmin} from "./middleware/admin-auth";
const app = new Hono()

app.use("*", dynamicCors);
admin.use("/api/admin", requireAdmin);
app.route('/api/admin', admin);  // all /api/admin/* routes
app.route('/api/auth', auth);    // all /api/auth/* routes

export default app;
