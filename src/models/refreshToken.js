const mongoose = require("mongoose");

const refreshTokenSchema = new mongoose.Schema({
  createdAt: {
    type: Date,
    default: Date.now,
    expires: 30,
  },
  token: {
    type: String,
    required: true,
    unique: true,
  },
});

module.exports = refreshTokenSchema;
