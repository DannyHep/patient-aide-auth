const mongoose = require("mongoose");
const Schema = mongoose.Schema;

const PasswordResetSchema = new Schema({
  email: String,
  resetString: String,
  createdAt: Number,
  expiresAt: Number,
});

const PasswordReset = mongoose.model("PasswordReset", PasswordResetSchema);

module.exports = PasswordReset;

// AUTH_EMAIL=onepatient@outlook.com
