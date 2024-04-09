const { isValidObjectId } = require("mongoose");

const getTwoFa = async function (auth, userId) {
  if (!userId || !isValidObjectId(userId)) {
    throw {
      code: "auth/userid-invalid",
      message: "The provided userid was invalid.",
      status: 400,
    };
  }
  try {
    const userDoc = await auth.models.User.findById(userId, "twofa");
    if (!userDoc) {
      throw {
        code: "auth/not-found",
        message: "Failed to find the user with the provided userId.",
        status: 404,
      };
    }
    if (!userDoc.twofa) {
      return null;
    }
    return userDoc.twofa;
  } catch (err) {
    throw {
      code: err.code || "auth/failed-to-find",
      message:
        err.message || "Failed to read the database for the provided userId.",
      status: err.status || 500,
    };
  }
};

module.exports = {
  getTwoFa,
};
