const {
  initAuth,
  generateAccessToken,
  generateRefreshToken,
  createUser,
  verifyAccessToken,
  verifyRefreshToken,
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

    const accessToken = await generateAccessToken(auth, user._id);
    const refreshToken = await generateRefreshToken(auth, user._id);
    const decodedAccessToken = await verifyAccessToken(auth, accessToken);
    const decodedRefreshToken = await verifyRefreshToken(auth, refreshToken);

    console.log("Decoded access token:", decodedAccessToken);
    console.log("Decoded refresh token:", decodedRefreshToken);
  } catch (error) {
    console.error(error);
  }
};

start();
