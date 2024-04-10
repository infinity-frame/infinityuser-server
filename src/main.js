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
const { generateTOTP, validateTOTP } = require("./otp");

const initAuth = (
  {
    accessTokenSecret,
    refreshTokenSecret,
    tempTokenSecret,
    db,
    enableLogs = false,
    refreshTokenExpiration = 8 * 24 * 60 * 60,
    accessTokenExpiration = 15 * 60,
  },
  twofaCustomSettings
) => {
  const User = db.model("User", userSchema);
  const RefreshToken = db.model(
    "RefreshToken",
    refreshTokenSchema(refreshTokenExpiration)
  );

  let twofa = null;
  if (twofaCustomSettings) {
    twofa = {
      keylength: twofaCustomSettings.keylength || 32,
      issuer: twofaCustomSettings.issuer,
      algorithm: twofaCustomSettings.algorithm || "SHA256",
      window: twofaCustomSettings.window || 1,
    };
  }

  if (enableLogs) {
    console.log("Auth initialized");
  }

  return {
    secrets: {
      accessTokenSecret,
      refreshTokenSecret,
      tempTokenSecret,
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
  generateTOTP,
  validateTOTP,
};
