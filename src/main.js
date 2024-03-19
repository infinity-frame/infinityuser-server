const userSchema = require("./models/user");
const refreshTokenSchema = require("./models/refreshToken");

const { createUser } = require("./user");
const { verifyAccessToken, getNewTokens } = require("./tokens");

const initAuth = ({
  accessTokenSecret,
  refreshTokenSecret,
  db,
  enableLogs,
}) => {
  const User = db.model("User", userSchema);
  const RefreshToken = db.model("RefreshToken", refreshTokenSchema);

  if (enableLogs) {
    console.log("Auth initialized");
  }

  return {
    secrets: {
      accessTokenSecret,
      refreshTokenSecret,
    },
    models: {
      User,
      RefreshToken,
    },
    settings: {
      enableLogs,
    },
  };
};

module.exports = {
  initAuth,
  createUser,
  verifyAccessToken,
  getNewTokens,
};
