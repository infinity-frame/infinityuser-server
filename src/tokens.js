const jwt = require("jsonwebtoken");

const verifyAccessToken = async (auth, token) => {
  if (auth.settings.enableLogs) {
    console.log("Verifying access token");
  }

  if (!token) {
    throw {
      code: "auth/missing-credentials",
      message: "Access token is required",
      status: 400,
    };
  }

  try {
    const payload = await jwt.verify(token, auth.secrets.accessTokenSecret);

    const userDoc = await auth.models.User.findById(payload.userId);
    if (!userDoc) {
      throw {
        code: "auth/user-not-found",
        message: "User not found",
        status: 404,
      };
    }
    if (userDoc.suspended) {
      throw {
        code: "auth/user-suspended",
        message: "User is suspended",
        status: 403,
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

  if (!token) {
    throw {
      code: "auth/missing-credentials",
      message: "Refresh token is required",
      status: 400,
    };
  }

  let payload;
  try {
    payload = await jwt.verify(token, auth.secrets.refreshTokenSecret);
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

  try {
    const tokenDoc = await auth.models.RefreshToken.findOne({ token });
    if (!tokenDoc) {
      console.log(
        "POSSIBLE REFRESH TOKEN INTERCEPTION FOR USER ID:",
        payload.userId
      );
      throw {
        code: "auth/invalid-refresh-token",
        message: "Invalid refresh token",
        status: 401,
      };
    }

    const userDoc = await auth.models.User.findById(payload.userId);
    if (!userDoc) {
      throw {
        code: "auth/user-not-found",
        message: "User not found",
        status: 404,
      };
    }
    if (userDoc.suspended) {
      throw {
        code: "auth/user-suspended",
        message: "User is suspended",
        status: 403,
      };
    }

    if (auth.settings.enableLogs) {
      console.log("Refresh token verified");
    }

    return userDoc;
  } catch (error) {
    throw {
      code: error.code || "auth/error-checking-refresh-token",
      message: error.message || "Error checking refresh token",
      status: error.status || 500,
    };
  }
};

const getNewTokens = async (auth, refreshToken) => {
  if (auth.settings.enableLogs) {
    console.log("Getting new tokens");
  }

  if (!refreshToken) {
    throw {
      code: "auth/missing-credentials",
      message: "Refresh token is required",
      status: 400,
    };
  }

  try {
    const userDoc = await verifyRefreshToken(auth, refreshToken);
    await auth.models.RefreshToken.deleteOne({ token: refreshToken });

    const accessToken = await generateAccessToken(auth, userDoc._id);
    const newRefreshToken = await generateRefreshToken(auth, userDoc._id);

    return {
      user: userDoc,
      accessToken,
      refreshToken: newRefreshToken,
    };
  } catch (error) {
    throw error;
  }
};

const generateAccessToken = async (auth, userId) => {
  if (auth.settings.enableLogs) {
    console.log(`Generating access token for user ${userId}`);
  }

  if (!userId) {
    throw {
      code: "auth/missing-credentials",
      message: "User id is required",
      status: 400,
    };
  }

  const payload = {
    userId,
  };

  const token = await jwt.sign(payload, auth.secrets.accessTokenSecret, {
    expiresIn: auth.settings.accessTokenExpiration,
  });

  if (auth.settings.enableLogs) {
    console.log(`Access token for user ${userId} created`);
  }

  return token;
};

const generateRefreshToken = async (auth, userId) => {
  if (auth.settings.enableLogs) {
    console.log(`Generating refresh token for user ${userId}`);
  }

  if (!userId) {
    throw {
      code: "auth/missing-credentials",
      message: "User id is required",
      status: 400,
    };
  }

  const payload = {
    userId,
  };

  const token = await jwt.sign(payload, auth.secrets.refreshTokenSecret, {
    expiresIn: auth.settings.refreshTokenExpiration,
  });

  try {
    await auth.models.RefreshToken.create({
      userId: userId,
      token,
    });

    if (auth.settings.enableLogs) {
      console.log(
        `Refresh token for user ${userId} created and saved to database`
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
