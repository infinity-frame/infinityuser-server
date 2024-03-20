const userSchema = require("./models/user");
const refreshTokenSchema = require("./models/refreshToken");
const {
  createUser,
  login,
  logout,
  deleteUser,
  updateEmail,
  isPasswordCorrect,
  getUser,
  updateUser,
  suspendUser,
  unsuspendUser,
} = require("./user");
const { verifyAccessToken, getNewTokens } = require("./tokens");
const authRouter = require("./router");
const { authMiddleware, passwordMiddleware } = require("./middlewares/auth");

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
  login,
  logout,
  deleteUser,
  isPasswordCorrect,
  getUser,
  authRouter,
  authMiddleware,
  passwordMiddleware,
  updateEmail,
  updateUser,
  suspendUser,
  unsuspendUser,
};
