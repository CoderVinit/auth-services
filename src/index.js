import dotenv from "dotenv";
dotenv.config();

import express from "express";
import cors from "cors";
import cookieParser from "cookie-parser";
import mongoose from "mongoose";
import authRouter from "./routes/auth.routes.js";

const app = express();
const PORT = process.env.PORT || 3001;

// MongoDB connection with retry (do not exit the process on failure)
const dbState = { connected: false, lastError: null };

const connectDBWithRetry = async (retryMs = 5000) => {
  const uri = process.env.MONGODB_URI;
  if (!uri) {
    console.error("❌ MONGODB_URI is not set");
    dbState.lastError = new Error("MONGODB_URI missing");
    return setTimeout(() => connectDBWithRetry(retryMs), retryMs);
  }
  try {
    // Allow providing DB name separately via MONGODB_DB when URI has no path
    const opts = {};
    if (process.env.MONGODB_DB) {
      opts.dbName = process.env.MONGODB_DB;
    }
    const conn = await mongoose.connect(uri, opts);
    dbState.connected = true;
    dbState.lastError = null;
    console.log(`✅ MongoDB Connected: ${conn.connection.host}/${conn.connection.name}`);
  } catch (error) {
    dbState.connected = false;
    dbState.lastError = error;
    console.error(`❌ MongoDB Connection Error: ${error.message}. Retrying in ${Math.floor(retryMs/1000)}s...`);
    setTimeout(() => connectDBWithRetry(retryMs), retryMs);
  }
};

// Middleware
app.use(cors({
  origin: true,
  credentials: true,
}));
app.use(express.json());
app.use(cookieParser());

// Routes
app.get("/health", (req, res) => {
  res.status(200).json({
    success: true,
    service: "auth-service",
    message: "Auth service is running",
    timestamp: new Date().toISOString(),
    db: {
      connected: dbState.connected,
      error: process.env.NODE_ENV === 'development' && dbState.lastError ? dbState.lastError.message : undefined
    }
  });
});

app.use("/api/auth", authRouter);

// Start server and connect to DB in background with retry
app.listen(PORT, () => {
  console.log(`🚀 Auth Service running on port ${PORT}`);
});

connectDBWithRetry();
