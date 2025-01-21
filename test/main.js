const { initAuth, authRouter, authMiddleware } = require("../src/main");
const mongoose = require("mongoose");
const express = require("express");
const { getUser, verifyRefreshToken, createUser } = require("../src/main.js");
const cors = require("cors");
const app = express();
require("dotenv").config();

const start = async () => {
  await mongoose.connect(process.env.DB_URI);
  const db = mongoose.connection;
  console.log(`Connected to database ${db.db.databaseName}`);

  const auth = initAuth({
    refreshTokenSecret: "refresh",
    accessTokenSecret: "access",
    tempTokenSecret: "temp",
    db,
    enableLogs: true,
    twofaSettings: {
      totpSettings: { issuer: "InfinityFrame" },
    },
  });

  app.use(cors());
  app.use(express.json());
  app.use((err, req, res, next) => {
    if (err instanceof SyntaxError) {
      res.status(400).json({
        code: "invalid-json",
        message: "Invalid JSON in request body.",
      });
    } else {
      console.log(err);
      res.status(500).json({
        code: "internal-server-error",
        message:
          "Error occured on the server, please contact the administrators if the issue persists.",
      });
    }
  });
  app.use("/auth", authRouter(auth));
  app.get("/test", authMiddleware(auth), function (req, res) {
    res.json({
      code: "success",
      message: "Authentication successful",
    });
  });
  app.get("/verify-refresh-token", async (req, res) => {
    const token = req.headers["authorization"];
    if (!token) {
      return res.status(400).json({
        code: "missing-token",
        message: "No token provided in Authorization header.",
      });
    }
    try {
      const result = await verifyRefreshToken(auth, token);
      res.json(result);
    } catch (err) {
      res.status(err.status || 500).json({
        code: err.code || "internal-server-error",
        message: err.message || "Error occured on the server.",
      });
    }
  });

  app.listen(3000);
  console.log("App listening on port 3000");
};

start();
