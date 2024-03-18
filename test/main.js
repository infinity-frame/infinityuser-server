const { initAuth, generateRefreshToken } = require("../src/main");
const mongoose = require("mongoose");

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
  });

  const refreshToken = await generateRefreshToken(
    "123",
    auth.refreshTokenSecret,
    db
  );
};

start();
