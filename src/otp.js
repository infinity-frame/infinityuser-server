const crypto = require("node:crypto");
const OTPAuth = require("otpauth");
const base32 = require("hi-base32");
const qrcode = require("qrcode");

const generateBase32Secret = function () {
  const buffer = crypto.randomBytes(128);
  const secret = base32.encode(buffer).replace(/=/g, "").substring(0, 32);
  return secret;
};

const generateTOTP = function () {
  const secret = generateBase32Secret();
  const totp = new OTPAuth.TOTP({
    issuer: "example.com",
    label: "example",
    algorithm: "SHA256",
    digits: 6,
    secret: secret,
  });
  qrcode.toFile("./test.png", totp.toString());
  return totp.toString();
};

const validateTOTP = function (code, secret) {
  const totp = new OTPAuth.TOTP({
    issuer: "example.com",
    label: "example",
    algorithm: "SHA256",
    digits: 6,
    secret: secret,
  });
  const delta = totp.validate({ token: code, window: 1 });
  if (delta == null) {
    return false;
  } else {
    return true;
  }
};

// console.log(generateTOTP());
// console.log(validateTOTP("602410", "7AOTJVQTKCFIWV27J5DTM3WEPXG4AB72"));
