const mongoose = require("mongoose");
const Schema = mongoose.Schema;

const UserSchema = new Schema({
  email: String,
  username: String,
  password: String,
  registrationCode: String,
  validationCode: String,
  verified: Boolean,
  questionnaireIds: [
    {
      type: String,
    },
  ],
  appointmentIds: [
    {
      type: String,
    },
  ],
  validicAccess: Boolean,
});

const User = mongoose.model("User", UserSchema);

module.exports = User;
