const bcrypt = require("bcrypt");
const {
  generateAccessToken,
  generateRefreshToken,
  verifyRefreshToken,
} = require("./tokens");

const createUser = async (auth, { email, password, data }) => {
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

  const salt = await bcrypt.genSalt();
  const hashedPassword = await bcrypt.hash(password, salt);
  let userDoc;
  try {
    userDoc = await auth.models.User.create({
      email,
      passwordHash: hashedPassword,
      suspended: false,
      data,
    });

    if (auth.settings.enableLogs) {
      console.log(`User with email ${email} created in db`);
    }
  } catch (error) {
    if (error.code === 11000) {
      throw {
        code: "auth/duplicate-email",
        message: "User with this email already exists",
        status: 409,
      };
    } else {
      throw {
        code: "auth/create-user-error",
        message: "Failed to create user",
        status: 500,
      };
    }
  }

  const accessToken = await generateAccessToken(auth, userDoc._id);
  const refreshToken = await generateRefreshToken(auth, userDoc._id);

  return {
    user: userDoc,
    accessToken,
    refreshToken,
  };
};

const login = async (auth, { email, password }) => {
  if (auth.settings.enableLogs) {
    console.log(`Logging in user with email ${email}`);
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

  const userDoc = await auth.models.User.findOne({ email });

  if (!userDoc) {
    throw {
      code: "auth/user-not-found",
      message: "User with this email does not exist",
      status: 404,
    };
  }

  const passwordMatch = await bcrypt.compare(password, userDoc.passwordHash);

  if (!passwordMatch) {
    throw {
      code: "auth/wrong-password",
      message: "The password is invalid",
      status: 401,
    };
  }

  const accessToken = await generateAccessToken(auth, userDoc._id);
  const refreshToken = await generateRefreshToken(auth, userDoc._id);

  return {
    user: userDoc,
    accessToken,
    refreshToken,
  };
};

const logout = async (auth, refreshToken) => {
  if (auth.settings.enableLogs) {
    console.log(`Logging out user with refresh token ${refreshToken}`);
  }

  await verifyRefreshToken(auth, refreshToken);

  try {
    await auth.models.RefreshToken.deleteOne({ token: refreshToken });
  } catch (error) {
    throw {
      code: "auth/delete-refresh-token-error",
      message: "Failed to delete refresh token",
      status: 500,
    };
  }
};

module.exports = { createUser, login, logout };
