const mongoose = require("mongoose");
const Schema = mongoose.Schema;

const MailVerificationSchema = new Schema({
  userId: String,
  uniqueString: String,
  createdAt: Number,
  expiresAt: Number,
});

const MailVerification = mongoose.model(
  "MailVerification",
  MailVerificationSchema
);

module.exports = MailVerification;
