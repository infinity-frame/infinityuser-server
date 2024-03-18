const { initAuth, createUser } = require("../src/main");
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
    enableLogs: true,
  });

  await createUser(auth, {
    email: "voj.hab@proton.me",
    password: "password123",
  });
};

start();
