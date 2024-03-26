const userSchema = require("./schemas/user");
const refreshTokenSchema = require("./schemas/refreshToken");
const {
  createUser,
  login,
  logout,
  deleteUser,
  updateEmail,
  isPasswordCorrect,
  getUser,
  updateUserData,
  suspendUser,
  unsuspendUser,
  changePassword,
} = require("./user");
const { verifyAccessToken, getNewTokens } = require("./tokens");
const authRouter = require("./router");
const { authMiddleware, passwordMiddleware } = require("./middlewares/auth");
const { generateBase32Secret, generateTOTP, validateTOTP } = require("./otp");

const initAuth = ({
  accessTokenSecret,
  refreshTokenSecret,
  db,
  enableLogs = false,
  refreshTokenExpiration = 8 * 24 * 60 * 60,
  accessTokenExpiration = 15 * 60,
  twofa = { keylength: 32, issuer, algorithm: "SHA256", window: 1 },
}) => {
  const User = db.model("User", userSchema);
  const RefreshToken = db.model(
    "RefreshToken",
    refreshTokenSchema(refreshTokenExpiration)
  );

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
      refreshTokenExpiration,
      accessTokenExpiration,
      twofa,
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
  updateUserData,
  suspendUser,
  unsuspendUser,
  changePassword,
  generateBase32Secret,
  generateTOTP,
  validateTOTP,
};
