const crypto = require("node:crypto");
const OTPAuth = require("otpauth");
const base32 = require("hi-base32");
const qrcode = require("qrcode");

const generateBase32Secret = function (auth) {
  console.info(
    `Generating a base32 secret for TOTP of length ${auth.settings.twofa.keylength}`
  );
  const buffer = crypto.randomBytes(auth.settings.twofa.keylength);
  const secret = base32.encode(buffer).replace(/=/g, "");
  console.info("Generated TOTP key successfuly");
  return secret;
};

const generateTOTP = function (auth, label) {
  if (
    typeof auth.settings.twofa == "undefined" ||
    typeof label == "undefined"
  ) {
    console.error(
      "InfinityUser TOTP Error: twoFA object or label was not defined."
    );
    return;
  }
  const secret = generateBase32Secret(auth);
  if (auth.settings.enableLogs) {
    console.info("Generating TOTP auth object");
  }

  const totp = new OTPAuth.TOTP({
    issuer: auth.settings.twofa.issuer,
    label: label,
    algorithm: "SHA256",
    digits: 6,
    secret: secret,
  });
  return { url: totp.toString(), secret: secret };
};

const validateTOTP = function (auth, code, secret) {
  if (
    typeof auth.settings.twofa == "undefined" ||
    typeof code == "undefined" ||
    typeof secret == "undefined"
  ) {
    console.error(
      "InfinityUser TOTP Error: twoFA object, label or secret were undefined during validation."
    );
    return;
  }
  if (auth.settings.enableLogs) {
    console.info(`Validating TOTP code ${code}`);
  }
  const totp = new OTPAuth.TOTP({
    algorithm: auth.settings.twofa.algorithm,
    digits: 6,
    secret: secret,
  });
  let delta;
  delta = totp.validate({ token: code, window: auth.settings.twofa.window });
  if (delta == null) {
    if (auth.settings.enableLogs) {
      console.log(`TOTP code ${code} was not found in the specified window.`);
    }
    return false;
  } else {
    if (auth.settings.enableLogs) {
      console.log(`TOTP code ${code} was found in the specified window.`);
    }
    return true;
  }
};

module.exports = {
  generateBase32Secret,
  generateTOTP,
  validateTOTP,
};
