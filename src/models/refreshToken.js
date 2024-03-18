const mongoose = require("mongoose");

const refreshTokenSchema = new mongoose.Schema({
  token: {
    type: String,
    required: true,
    unique: true,
  },
  expireAt: {
    type: Date,
    required: true,
  },
});

module.exports = refreshTokenSchema;
