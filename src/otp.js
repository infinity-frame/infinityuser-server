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
const generateTOTP = async function (auth, userId) {
  if (
    typeof auth.settings.twofa == "undefined" ||
    typeof userId == "undefined"
  ) {
    throw {
      code: "auth/totp/no-params",
      message: "Auth object or userId was not defined.",
      status: 500,
    };
  }
  if (!isValidObjectId(userId)) {
    throw {
      code: "auth/totp/userid-invalid",
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
      code: err.code || "auth/failed-to-find",
      message:
        err.message || "Failed to read the database for the provided userId.",
      status: err.status || 500,
      raw: err,
    };
  }
  const secret = generateBase32Secret(auth);
  userDoc.twofa.totp.push(secret);
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
    await userDoc.save();
  } catch (err) {
    throw {
      code: "auth/totp/failed-to-save",
      message: "The document couldn't be saved to the database.",
      status: 500,
      raw: err,
    };
  }
  if (auth.settings.enableLogs) {
    console.info(`Generated a new TOTP for user ${userDoc._id}`);
  }
  return { url: totp.toString(), secret: secret };
};

const validateTOTP = async function (auth, code, userId) {
  if (
    typeof auth.settings.twofa == "undefined" ||
    typeof code == "undefined" ||
    typeof userId == "undefined"
  ) {
    throw {
      code: "auth/totp/no-params",
      message: "Auth object, label or secret was not defined.",
      status: 500,
    };
  }
  if (auth.settings.enableLogs) {
    console.info(`Validating TOTP code ${code} for user ${userId}`);
  }
  if (!isValidObjectId(userId)) {
    throw {
      code: "auth/totp/userid-invalid",
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
      code: err.code || "auth/failed-to-find",
      message:
        err.message || "Failed to read the database for the provided userId.",
      status: err.status || 500,
      raw: err,
    };
  }
  if (!userDoc.twofa || !userDoc.twofa.totp || userDoc.twofa.totp.length == 0) {
    throw {
      code: err.code || "auth/totp-not-setup",
      message: err.message || "TOTP is not setup for the specified user.",
      status: err.status || 400,
      raw: err,
    };
  }
  let valid = false;
  for (const secret of userDoc.twofa.totp) {
    const totp = new OTPAuth.TOTP({
      algorithm: auth.settings.twofa.algorithm,
      digits: 6,
      secret: secret,
    });
    let delta;
    delta = totp.validate({ token: code, window: auth.settings.twofa.window });
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

module.exports = {
  generateTOTP,
  validateTOTP,
};
