const jwt = require("jsonwebtoken");

const verifyAccessToken = async (auth, token) => {
  if (auth.settings.enableLogs) {
    console.log("Verifying access token");
  }

  try {
    const payload = await jwt.verify(token, auth.secrets.accessTokenSecret);

    const userDoc = await auth.models.User.findById(payload.uid);
    if (!userDoc) {
      throw {
        code: "auth/user-not-found",
        message: "User not found",
        status: 404,
      };
    }

    if (auth.settings.enableLogs) {
      console.log("Access token verified");
    }

    return userDoc;
  } catch (error) {
    throw {
      code: "auth/invalid-access-token",
      message: "Invalid access token",
      status: 401,
    };
  }
};

const verifyRefreshToken = async (auth, token) => {
  if (auth.settings.enableLogs) {
    console.log("Verifying refresh token");
  }

  try {
    const payload = await jwt.verify(token, auth.secrets.refreshTokenSecret);

    try {
      const tokenDoc = await auth.models.RefreshToken.findOne({ token });
      if (!tokenDoc) {
        throw {
          code: "auth/invalid-refresh-token",
          message: "Invalid refresh token",
          status: 401,
        };
      }

      const userDoc = await auth.models.User.findById(payload.uid);
      if (!userDoc) {
        throw {
          code: "auth/user-not-found",
          message: "User not found",
          status: 404,
        };
      }

      if (auth.settings.enableLogs) {
        console.log("Refresh token verified");
      }

      return userDoc;
    } catch (error) {
      throw {
        code: "auth/error-checking-refresh-token",
        message: "Invalid refresh token",
        status: 401,
      };
    }
  } catch (error) {
    if (error.name === "TokenExpiredError") {
      throw {
        code: "auth/refresh-token-expired",
        message: "Refresh token expired, you need to reauthenticate",
        status: 401,
      };
    } else {
      throw {
        code: "auth/invalid-refresh-token",
        message: "Invalid refresh token",
        status: 401,
      };
    }
  }
};

const getNewTokens = async (auth, refreshToken) => {
  try {
    const userDoc = await verifyRefreshToken(auth, refreshToken);
    await auth.models.RefreshToken.deleteOne({ token: refreshToken });

    const accessToken = await generateAccessToken(auth, userDoc._id);
    const newRefreshToken = await generateRefreshToken(auth, userDoc._id);

    return {
      accessToken,
      refreshToken: newRefreshToken,
    };
  } catch (error) {
    throw error;
  }
};

const generateAccessToken = async (auth, uid) => {
  if (auth.settings.enableLogs) {
    console.log(`Generating access token for user ${uid}`);
  }

  const payload = {
    uid,
  };

  const token = await jwt.sign(payload, auth.secrets.accessTokenSecret, {
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

  const token = await jwt.sign(payload, auth.secrets.refreshTokenSecret, {
    expiresIn: "8d",
  });

  try {
    await auth.models.RefreshToken.create({
      token,
    });

    if (auth.settings.enableLogs) {
      console.log(
        `Refresh token for user ${uid} created and saved to database`
      );
    }
  } catch (error) {
    throw {
      code: "auth/save-refresh-token-error",
      message: "Failed to save refresh token",
      status: 500,
    };
  }

  return token;
};

module.exports = {
  verifyAccessToken,
  verifyRefreshToken,
  getNewTokens,
  generateAccessToken,
  generateRefreshToken,
};
