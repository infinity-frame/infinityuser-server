const {
  initAuth,
  createUser,
  verifyAccessToken,
  getNewTokens,
} = require("../src/main");
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

  try {
    const user = await createUser(auth, {
      email: "example@example.com",
      password: "password123",
    });

    console.log(user);

    const decodedAccessToken = await verifyAccessToken(auth, user.accessToken);
    console.log("Decoded access token:", decodedAccessToken);

    console.log("Waiting for 5 seconds...");
    await new Promise((resolve) => setTimeout(resolve, 5000));

    const newTokens = await getNewTokens(auth, user.refreshToken);
    console.log("New tokens:", newTokens);
  } catch (error) {
    console.error(error);
  }
};

start();
