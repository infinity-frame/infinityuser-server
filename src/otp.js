const crypto = require("node:crypto");
const OTPAuth = require("otpauth");
const base32 = require("hi-base32");
const { isValidObjectId } = require("mongoose");

const generateBase32Secret = function (auth) {
  if (auth.settings.enableLogs) {
    console.info(
      `Generating a base32 secret for TOTP of length ${auth.settings.twofa.keylength}`
    );
  }
  const buffer = crypto.randomBytes(auth.settings.twofa.keylength);
  const secret = base32.encode(buffer).replace(/=/g, "");
  console.info("Generated TOTP key successfuly");
  return secret;
};
const generateTOTP = async function (auth, userId, identifier) {
  if (!auth.settings.twofa) {
    throw {
      code: "auth/totp/invalid-auth-object",
      message: "Auth object twofa was not defined.",
      status: 500,
    };
  }
  if (!userId || !identifier) {
    throw {
      code: "auth/no-params",
      message: "UserId or identifier was not defined.",
      status: 400,
    };
  }
  if (!isValidObjectId(userId)) {
    throw {
      code: "auth/userid-invalid",
      message: "The provided userid was invalid.",
      status: 400,
    };
  }
  let userDoc;
  try {
    userDoc = await auth.models.User.findById(userId);
    if (!userDoc) {
      throw {
        code: "auth/user-not-found",
        message: "User not found",
        status: 404,
      };
    }
  } catch (err) {
    throw {
      code: err.code || "auth/totp/failed-to-find",
      message:
        err.message || "Failed to read the database for the provided userId.",
      status: err.status || 500,
    };
  }
  if (!!userDoc.twofa.totp) {
    let duplicate = false;
    for (const authenticator of userDoc.twofa.totp) {
      if (authenticator.identifier == identifier) {
        duplicate = true;
        break;
      }
    }
    if (duplicate) {
      throw {
        code: "auth/identifier-exists",
        message: "A TOTP with this identifier already exists.",
        status: 400,
      };
    }
  }
  const secret = generateBase32Secret(auth);
  userDoc.twofa.totp.push({ identifier: identifier, secret: secret });
  if (auth.settings.enableLogs) {
    console.info("Generating TOTP auth object");
  }
  const totp = new OTPAuth.TOTP({
    issuer: auth.settings.twofa.issuer,
    label: userDoc.email,
    algorithm: auth.settings.twofa.algorithm,
    digits: 6,
    secret: secret,
  });
  if (auth.settings.enableLogs) {
    console.info(`Generated TOTP auth object`);
  }
  try {
    // userDoc.save() doesn't work for some reason ???
    await auth.models.User.updateOne({ _id: userDoc._id }, userDoc);
  } catch (err) {
    throw {
      code: "auth/totp/failed-to-save",
      message: "The document couldn't be saved to the database.",
      status: 500,
    };
  }
  if (auth.settings.enableLogs) {
    console.info(`Generated a new TOTP for user ${userDoc._id}`);
  }
  return { url: totp.toString(), secret: secret };
};

const validateTOTP = async function (auth, code, userId) {
  if (typeof auth.settings.twofa == "undefined") {
    throw {
      code: "auth/totp/invalid-auth-object",
      message: "Auth object twofa was not defined.",
      status: 500,
    };
  }
  if (typeof code == "undefined" || typeof userId == "undefined") {
    throw {
      code: "auth/no-params",
      message: "UserId or code was not defined.",
      status: 400,
    };
  }
  if (auth.settings.enableLogs) {
    console.info(`Validating TOTP code ${code} for user ${userId}`);
  }
  if (!isValidObjectId(userId)) {
    throw {
      code: "auth/userid-invalid",
      message: "The provided userid was invalid.",
      status: 400,
    };
  }
  let userDoc;
  try {
    userDoc = await auth.models.User.findById(userId);
    if (!userDoc) {
      throw {
        code: "auth/user-not-found",
        message: "User not found",
        status: 404,
      };
    }
  } catch (err) {
    throw {
      code: err.code || "auth/totp/failed-to-find",
      message:
        err.message || "Failed to read the database for the provided userId.",
      status: err.status || 500,
    };
  }
  if (!userDoc.twofa || !userDoc.twofa.totp || userDoc.twofa.totp.length == 0) {
    throw {
      code: err.code || "auth/totp-not-setup",
      message: err.message || "TOTP is not setup for the specified user.",
      status: err.status || 400,
    };
  }
  let valid = false;
  for (const authenticator of userDoc.twofa.totp) {
    const totp = new OTPAuth.TOTP({
      algorithm: auth.settings.twofa.algorithm,
      digits: 6,
      secret: authenticator.secret,
    });
    let delta;
    delta = totp.validate({
      token: code,
      window: auth.settings.twofa.window,
    });
    if (delta != null) {
      valid = true;
      if (auth.settings.enableLogs) {
        console.log(
          `TOTP code ${code} for ${userId} was found in the specified window.`
        );
      }
      break;
    }
  }
  return valid;
};

const removeTOTP = async function (auth, userId, identifier) {
  if (!auth.settings.twofa) {
    throw {
      code: "auth/totp/invalid-auth-object",
      message: "Auth object twofa was not defined.",
      status: 500,
    };
  }
  if (auth.settings.enableLogs) {
    console.info(`Removing TOTP ${identifier} for user ${userId}`);
  }
  if (!userId || !identifier) {
    throw {
      code: "auth/no-params",
      message: "UserId or identifier was not defined.",
      status: 400,
    };
  }
  if (!isValidObjectId(userId)) {
    throw {
      code: "auth/userid-invalid",
      message: "The provided userid was invalid.",
      status: 400,
    };
  }
  try {
    let userDoc = await auth.models.User.findById(userId);
    if (!userDoc) {
      throw {
        code: "auth/user-not-found",
        message: "User not found",
        status: 404,
      };
    }
    let index = null;
    for (const authenticatorIndex in userDoc.twofa.totp) {
      if (userDoc.twofa.totp[authenticatorIndex].identifier == identifier) {
        index = authenticatorIndex;
        break;
      }
    }
    if (auth.settings.enableLogs) {
      console.info(`Identifier ${identifier} found on user ${userId}`);
    }
    if (index == null) {
      throw {
        code: "auth/identifier-not-found",
        message: "Authenticator with the provided identifier not found",
        status: 404,
      };
    }
    userDoc.twofa.totp.splice(index, 1);
    await auth.models.User.updateOne({ _id: userId }, userDoc);
  } catch (err) {
    throw {
      code: err.code || "auth/totp/failed-to-find",
      message:
        err.message || "Failed to read the database for the provided userId.",
      status: err.status || 500,
    };
  }
  if (auth.settings.enableLogs) {
    console.info(`TOTP ${identifier} was removed from user ${userId}`);
  }
  return true;
};

module.exports = {
  generateTOTP,
  validateTOTP,
  removeTOTP,
};
