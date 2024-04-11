const { isValidObjectId } = require("mongoose");
const { validateTOTP } = require("./totp");

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
      try {
        await validateTOTP(auth, String(code), userId);
      } catch (err) {
        throw {
          code: err.code || "auth/internal-server-error",
          message:
            err.message ||
            "Unknown internal server error occured, please contact the administrators.",
          status: err.status || 500,
        };
      }
      break;
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
