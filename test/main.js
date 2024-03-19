const { initAuth, authRouter } = require("../src/main");
const mongoose = require("mongoose");
const express = require("express");
const app = express();

const start = async () => {
  await mongoose.connect(
    "mongodb+srv://vojtech:ErXXh4xx3j7VewTI@maincluster.qqslnqr.mongodb.net/?retryWrites=true&w=majority&appName=MainCluster"
  );
  const db = mongoose.connection;
  console.log(`App connected to database ${db.db.databaseName}`);

  const auth = initAuth({
    accessTokenSecret: "access",
    refreshTokenSecret: "refresh",
    db,
    enableLogs: true,
  });

  app.use(express.json());
  app.use("/auth", authRouter(auth));

  await app.listen(3000);
  console.log("App listening on port 3000");
};

start();
