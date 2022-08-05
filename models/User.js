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
  reminder: {
    minutes: Number,
    hours: Number,
  },
  careContacts: [
    {
      firstName: String,
      lastName: String,
      contactNumber: String,
      address: {
        addressLine1: String,
        addressLine2: String,
        city: String,
        postCode: String,
      },
      relationship: String,
      email: String,
      isDelegate: String,
    },
  ],
  PASID: String,
});

const User = mongoose.model("User", UserSchema);

module.exports = User;
