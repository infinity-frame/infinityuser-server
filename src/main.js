const userSchema = require("./models/user");
const refreshTokenSchema = require("./models/refreshToken");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

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

const generateAccessToken = (auth, uid) => {
  if (auth.settings.enableLogs) {
    console.log(`Generating access token for user ${uid}`);
  }

  const payload = {
    uid,
  };

  const token = jwt.sign(payload, auth.secrets.accessTokenSecret, {
    expiresIn: "10m",
  });

  if (auth.settings.enableLogs) {
    console.log(`Access token for user ${uid} created`);
  }

  return token;
};

const generateRefreshToken = async (auth, uid) => {
  if (auth.settings.enableLogs) {
    console.log(`Generating refresh token for user ${uid}`);
  }

  const payload = {
    uid,
  };

  const token = jwt.sign(payload, auth.secrets.refreshTokenSecret, {
    expiresIn: "8d",
  });

  await auth.models.RefreshToken.create({
    token,
  });

  if (auth.settings.enableLogs) {
    console.log(`Refresh token for user ${uid} created and saved to database`);
  }

  return token;
};

module.exports = {
  initAuth,
  generateRefreshToken,
};
