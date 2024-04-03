const { initAuth, authRouter } = require("../src/main");
const mongoose = require("mongoose");
const express = require("express");
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
    db,
    enableLogs: true,
  });

  app.use(cors());
  app.use(express.json());
  app.use("/auth", authRouter(auth));

  await app.listen(3000);
  console.log("App listening on port 3000");
};

start();
