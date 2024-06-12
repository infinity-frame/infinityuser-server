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

    const userDoc = await auth.models.User.findById(payload.userId).select(
      "-passwordHash"
    );
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

    const userDoc = await auth.models.User.findById(payload.userId).select(
      "-passwordHash"
    );
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

    const userDocSafe = userDoc.toObject();

    if (userDocSafe.twofa) {
      if (userDocSafe.twofa.totp) {
        for (const authenticator of userDocSafe.twofa.totp) {
          delete authenticator.secret;
        }
      }
    }

    return {
      user: userDocSafe,
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

const createNewTempToken = async function (auth, userId, totp) {
  if (!auth.secrets.tempTokenSecret) {
    throw {
      code: "auth/two-fa/missing-temporary-secret-key",
      message: "Missing tempSecretKey.",
      status: 500,
    };
  }

  if (auth.settings.enableLogs) {
    console.log(`Generating temporary token for user ${userId}`);
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

  const token = await jwt.sign(payload, auth.secrets.tempTokenSecret, {
    expiresIn: auth.settings.tempTokenExpiration || "10m",
  });

  if (auth.settings.enableLogs) {
    console.log(`Temporary token for user ${userId} created.`);
  }

  return token;
};

const verifyTempToken = async (auth, token) => {
  if (auth.settings.enableLogs) {
    console.log("Verifying temporary token");
  }

  if (!token) {
    throw {
      code: "auth/missing-credentials",
      message: "Temporary token is required",
      status: 400,
    };
  }

  try {
    const payload = await jwt.verify(token, auth.secrets.tempTokenSecret);

    const userDoc = await auth.models.User.findById(
      payload.userId,
      "twofa suspended"
    );
    if (!userDoc) {
      throw {
        code: "auth/user-not-found",
        message: "User not found",
        status: 404,
      };
    }
    if (!userDoc.twofa) {
      throw {
        code: "auth/twofa-disabled",
        message: "User has two-fa disabled",
        status: 400,
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
      console.log("Temporary token verified");
    }

    const userDocSafe = userDoc.toObject();
    if (userDocSafe.twofa.totp) {
      for (const authenticator of userDocSafe.twofa.totp) {
        delete authenticator.secret;
      }
    }

    return { _id: userDocSafe._id, twofa: userDocSafe.twofa };
  } catch (error) {
    throw {
      code: "auth/invalid-temp-token",
      message: "Invalid temporary token",
      status: 401,
    };
  }
};

const removeAllRefreshTokens = async (auth, userId) => {
  await auth.models.RefreshToken.deleteMany({ userId });
};

module.exports = {
  verifyAccessToken,
  verifyRefreshToken,
  getNewTokens,
  generateAccessToken,
  generateRefreshToken,
  createNewTempToken,
  verifyTempToken,
  removeAllRefreshTokens,
};
