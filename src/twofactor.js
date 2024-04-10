const { isValidObjectId } = require("mongoose");
const { validateTOTP } = require("./otp");

const verifyTwoFa = async function (auth, method, userId, code) {
  if (auth.settings.twofa == null) {
    throw {
      code: "auth/two-fa/missing-twofa",
      message: "Twofa is not configured.",
      status: 500,
    };
  }
  if (!method) {
    throw {
      code: "auth/missing-method",
      message: "Missing the method to authenticate by.",
      status: 400,
    };
  }
  if (!code) {
    throw {
      code: "auth/missing-code",
      message: "Missing code to verify.",
      status: 400,
    };
  }
  let verified = false;
  switch (method) {
    case "totp":
      if (await validateTOTP(auth, String(code), userId)) {
        break;
      }
      throw {
        code: "auth/invalid-totp",
        message: "The TOTP code was not found in the specified window.",
        status: 403,
      };
    default:
      throw {
        code: "invalid-method",
        message: "The verification method is invalid.",
        status: 400,
      };
  }
};

module.exports = {
  verifyTwoFa,
};
