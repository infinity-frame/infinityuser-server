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
    console.log(`Logging out user`);
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

const deleteUser = async (auth, userId) => {
  if (auth.settings.enableLogs) {
    console.log(`Deleting user with id ${userId}`);
  }

  if (!userId) {
    throw {
      code: "auth/missing-credentials",
      message: "User id is required",
      status: 400,
    };
  }

  try {
    await auth.models.User.deleteOne({ _id: userId });
    await auth.models.RefreshToken.deleteMany({ userId: userId });

    if (auth.settings.enableLogs) {
      console.log(`User with id ${userId} deleted`);
    }
  } catch (error) {
    throw {
      code: "auth/delete-user-error",
      message: "Failed to delete user",
      status: 500,
    };
  }
};

const updateEmail = async (auth, { userId, newEmail }) => {
  if (auth.settings.enableLogs) {
    console.log(`Updating email for user with id ${userId}`);
  }

  if (!newEmail) {
    throw {
      code: "auth/missing-credentials",
      message: "New email is required",
      status: 400,
    };
  }

  const emailRegex =
    /(?:[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*|"(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]|\\[\x01-\x09\x0b\0c\x0e-\x7f])*")@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\[(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?|[a-z0-9-]*[a-z0-9]:(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21-\x5a\x53-\x7f]|\\[\x01-\x09\x0b\0c\x0e-\x7f])+)\])/;
  if (!emailRegex.test(newEmail)) {
    throw {
      code: "auth/invalid-email",
      message: "The email address is badly formatted",
      status: 400,
    };
  }

  try {
    const userDoc = await auth.models.User.findByIdAndUpdate(
      userId,
      { email: newEmail },
      { new: true }
    );

    if (!userDoc) {
      throw {
        code: "auth/user-not-found",
        message: "User not found",
        status: 404,
      };
    }

    if (auth.settings.enableLogs) {
      console.log(`Email for user with id ${userId} updated`);
    }

    return userDoc;
  } catch (error) {
    throw {
      code: "auth/update-email-error",
      message: "Failed to update email",
      status: 500,
    };
  }
};

const isPasswordCorrect = async (auth, { userId, password, passwordHash }) => {
  if (auth.settings.enableLogs) {
    console.log(`Checking password for user with id ${userId}`);
  }

  if (!password || !userId) {
    throw {
      code: "auth/missing-credentials",
      message: "User id and password are required",
      status: 400,
    };
  }

  if (!passwordHash) {
    try {
      if (!userDoc) {
        userDoc = await getUser(auth, userId);
      }

      const passwordMatch = await bcrypt.compare(
        password,
        userDoc.passwordHash
      );

      if (auth.settings.enableLogs) {
        console.log(`Password for user with id ${userId} is correct`);
      }

      return passwordMatch;
    } catch (error) {
      throw {
        code: "auth/check-password-error",
        message: "Failed to check password",
        status: 500,
      };
    }
  } else {
    const passwordMatch = await bcrypt.compare(password, passwordHash);
    return passwordMatch;
  }
};

const getUser = async (auth, userId) => {
  if (auth.settings.enableLogs) {
    console.log(`Getting user with id ${userId}`);
  }

  if (!userId) {
    throw {
      code: "auth/missing-credentials",
      message: "User id is required",
      status: 400,
    };
  }

  try {
    const userDoc = await auth.models.User.findById(userId);

    if (!userDoc) {
      throw {
        code: "auth/user-not-found",
        message: "User not found",
        status: 404,
      };
    }

    if (auth.settings.enableLogs) {
      console.log(`User with id ${userId} found`);
    }

    return userDoc;
  } catch (error) {
    throw {
      code: "auth/get-user-error",
      message: "Failed to get user",
      status: 500,
    };
  }
};

module.exports = {
  createUser,
  login,
  logout,
  deleteUser,
  updateEmail,
  isPasswordCorrect,
  getUser,
};
