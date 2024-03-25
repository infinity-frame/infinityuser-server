const mongoose = require("mongoose");

const refreshTokenSchema = (auth) => {
  const refreshTokenSchema = new mongoose.Schema({
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      required: true,
      ref: "User",
    },
    createdAt: {
      type: Date,
      default: Date.now,
      expires: auth.settings.refreshTokenExpiration,
    },
    token: {
      type: String,
      required: true,
      unique: true,
    },
  });

  return refreshTokenSchema;
};

module.exports = refreshTokenSchema;
