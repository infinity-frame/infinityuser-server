const mongoose = require("mongoose");

const userSchema = new mongoose.Schema(
  {
    email: {
      type: String,
      required: true,
      unique: true,
    },
    displayName: {
      type: String,
      required: false,
    },
    passwordHash: {
      type: String,
      required: true,
    },
    suspended: {
      type: Boolean,
      required: true,
    },
    data: {
      type: Map,
      of: String,
      required: false,
    },
  },
  { timestamps: true }
);

module.exports = mongoose.model("User", userSchema);
