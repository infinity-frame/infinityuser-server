const User = require("./models/user");
const refreshTokenSchema = require("./models/refreshToken");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const initAuth = ({ accessTokenSecret, refreshTokenSecret, db }) => {
  return {
    accessTokenSecret,
    refreshTokenSecret,
  };
};

const generateAccessToken = (id, accessTokenSecret) => {
  const payload = {
    id,
  };

  return jwt.sign(payload, accessTokenSecret, {
    expiresIn: "10m",
  });
};

const generateRefreshToken = async (id, refreshTokenSecret, db) => {
  const payload = {
    id,
  };

  const token = jwt.sign(payload, refreshTokenSecret, {
    expiresIn: "8d",
  });

  console.log(token);

  const RefreshToken = db.model("RefreshToken", refreshTokenSchema);

  await RefreshToken.create({
    userId: id,
    token,
  });

  console.log("token created");

  return token;
};

module.exports = {
  initAuth,
  generateRefreshToken,
};
