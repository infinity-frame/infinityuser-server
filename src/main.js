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

const createUser = async (
  auth,
  { email, password, username, displayName, data }
) => {
  if (auth.settings.enableLogs) {
    console.log(`Creating user with email ${email}`);
  }

  if (!email || !password) {
    throw {
      code: "auth/missing-credentials",
      message: "Email and password are required",
      status: 400,
    };
  }

  const emailRegex =
    /(?:[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*|"(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])*")@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\[(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?|[a-z0-9-]*[a-z0-9]:(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21-\x5a\x53-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])+)\])/;
  if (!emailRegex.test(email)) {
    throw {
      code: "auth/invalid-email",
      message: "The email address is badly formatted",
      status: 400,
    };
  }

  const passwordRegex = /^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8,32}$/;
  if (!passwordRegex.test(password)) {
    throw {
      code: "auth/invalid-password",
      message:
        "Password should be 8-32 characters long and contain at least one letter and one number",
      status: 400,
    };
  }

  if (username) {
    const usernameRegex = /^[a-zA-Z0-9_-]{3,20}$/;
    if (!usernameRegex.test(username)) {
      throw {
        code: "auth/invalid-username",
        message:
          "Username should be 3-20 characters long and contain only alphanumeric characters, dashes and underscores",
        status: 400,
      };
    }
  }

  if (displayName) {
    const displayNameRegex = /^[a-zA-Z0-9_-\s]{3,50}$/;
    if (!displayNameRegex.test(displayName)) {
      throw {
        code: "auth/invalid-display-name",
        message:
          "Display name should be 3-50 characters long and contain only alphanumeric characters, spaces, dashes and underscores",
        status: 400,
      };
    }
  }

  try {
    const salt = await bcrypt.genSalt();
    const hashedPassword = await bcrypt.hash(password, salt);

    const userDoc = await auth.models.User.create({
      email,
      passwordHash: hashedPassword,
      suspended: false,
      username,
      displayName,
      data,
    });

    if (auth.settings.enableLogs) {
      console.log(`User with email ${email} created`);
    }

    const accessToken = await generateAccessToken(auth, userDoc._id);
    const refreshToken = await generateRefreshToken(auth, userDoc._id);

    return {
      user: userDoc,
      accessToken,
      refreshToken,
    };
  } catch (error) {
    throw {
      code: "auth/create-user-error",
      message: "Failed to create user",
      status: 500,
    };
  }
};

module.exports = {
  initAuth,
  createUser,
  verifyAccessToken,
  getNewTokens,
};
