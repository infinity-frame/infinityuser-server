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
const { generateTOTP, validateTOTP } = require("./twofa/totp");
const { verifyTwoFa } = require("./twofa/twofactor");

const initAuth = ({
  accessTokenSecret,
  refreshTokenSecret,
  tempTokenSecret,
  db,
  enableLogs = false,
  refreshTokenExpiration = 8 * 24 * 60 * 60,
  accessTokenExpiration = 15 * 60,
  twofaSettings = null,
}) => {
  const User = db.model("User", userSchema);
  const RefreshToken = db.model(
    "RefreshToken",
    refreshTokenSchema(refreshTokenExpiration)
  );

  let twofa = null;
  if (twofaSettings) {
    if (enableLogs) {
      console.info("Initializing twofa");
    }
    twofa = {};
    if (twofaSettings.totpSettings) {
      twofa.totp = {
        issuer: twofaSettings.totpSettings.issuer,
        keylength: twofaSettings.totpSettings.keylength || 32,
        algorithm: twofaSettings.totpSettings.algorithm || "SHA256",
        window: twofaSettings.totpSettings.window || 1,
      };
    }
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
  verifyTwoFa,
};
