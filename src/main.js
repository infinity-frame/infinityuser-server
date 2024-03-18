const userSchema = require("./models/user");
const refreshTokenSchema = require("./models/refreshToken");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const initAuth = ({ accessTokenSecret, refreshTokenSecret, db }) => {
  const User = db.model("User", userSchema);
  const RefreshToken = db.model("RefreshToken", refreshTokenSchema);

  return {
    secrets: {
      accessTokenSecret,
      refreshTokenSecret,
    },
    models: {
      User,
      RefreshToken,
    },
  };
};

const generateAccessToken = (auth, uid) => {
  const payload = {
    uid,
  };

  return jwt.sign(payload, auth.secrets.accessTokenSecret, {
    expiresIn: "10m",
  });
};

const generateRefreshToken = async (auth, uid) => {
  const payload = {
    uid,
  };

  const token = jwt.sign(payload, auth.secrets.refreshTokenSecret, {
    expiresIn: "8d",
  });

  console.log(token);

  await auth.models.RefreshToken.create({
    token,
  });

  console.log("token created");

  return token;
};

module.exports = {
  initAuth,
  generateRefreshToken,
};
