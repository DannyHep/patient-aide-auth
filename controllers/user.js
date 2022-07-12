const utils = require("../utils");

// mongodb user model
const User = require("../models/User");
const MailVerification = require("../models/MailVerification");
const PasswordReset = require("../models/PasswordReset");

// password handler
const bcrypt = require("bcrypt");

// email handler
// const nodemailer = require("nodemailer");
const sendgridMail = require("@sendgrid/mail");
sendgridMail.setApiKey(process.env.SENDGRID_API_KEY);

// unique string
const { v4: uuidv4 } = require("uuid");

// env variable
require("dotenv").config();

// testing sendgrid config
const sendMail = async (options) => {
  try {
    await sendgridMail.send(options);
    console.log("Message was sent successfully");
  } catch (error) {
    console.log(error);
    if (error.response) {
      console.log(error.response.body);
    }
  }
};

exports.checkUserData = async (req, res) => {
  User.find(req.query)
    .then((data) => {
      if (data.length) {
        res.json({
          status: "Pending",
          message: "already taken",
        });
      } else {
        res.json({
          status: "Pending",
          message: "is unique",
        });
      }
    })
    .catch((error) => {
      console.log(error);
      res.json({
        status: "Failed",
        message: "An error ocurred when checking for the existing username",
      });
    });
};

exports.signup = async (req, res) => {
  const { email, password, registrationCode, validationCode } = req.body;
  if (utils.containsEmptyCredentials(req.body)) {
    res.json({
      status: "Failed",
      message: "Empty input fields",
    });
  } else if (!utils.validateEmail(email)) {
    res.json({
      status: "Failed",
      message: "Invalid email!",
    });
  } else if (password.length < 8) {
    res.json({
      status: "Failed",
      message: "Password is too short!",
    });
  } else if (registrationCode.length < 4) {
    res.json({
      status: "Failed",
      message: "Registration code does not correspond!",
    });
  } else if (validationCode.length < 4) {
    res.json({
      status: "Failed",
      message: "Validation code does not correspond!",
    });
  } else {
    // check is the user already exists
    try {
      await User.find({ email }).then((result) => {
        // check if email exists (is provided by NHS) and is not yet verified
        if (!result.length) {
          res.json({
            status: "Failed",
            message: "An error ocurred while checking for existing user!",
          });
        } else if (result.length > 1) {
          res.json({
            status: "Failed",
            message:
              "This email address is duplicate, please contact your administrator",
          });
        } else if (result[0].verified) {
          res.json({
            status: "Failed",
            message: "This email address is already verified",
          });
        } else if (result[0].registrationCode !== registrationCode) {
          res.json({
            status: "Failed",
            message: "Please check your Registration Code",
          });
        } else if (result[0].validationCode !== validationCode) {
          res.json({
            status: "Failed",
            message: "Please check your Validation Code",
          });
        } else {
          //create the new user
          const saltRounds = 10;
          bcrypt.hash(password, saltRounds).then((hashedPassword) => {
            User.findOneAndUpdate(
              { _id: result[0]._id },
              { password: hashedPassword, validicAccess: false },
              { returnDocument: "after" }
            )
              .then((result) => {
                // handle account verification
                exports.sendVerificationEmail(result, res);
              })
              .catch((error) => {
                console.log(error);
                res.json({
                  status: "Failed",
                  message: "An error ocurred while saving user's account!",
                });
              });
          });
        }
      });
    } catch (error) {
      console.log(error);
      res.json({
        status: "Failed",
        message: "An error ocurred while checking for existing user!",
      });
    }
  }
};

exports.sendVerificationEmail = ({ email, _id }, res) => {
  // url to be used in the email
  const currentUrl = process.env.REACT_APP_LOCAL_URL;
  const uniqueString = uuidv4() + _id;
  //mail options
  const mailOptions = {
    from: process.env.AUTH_EMAIL,
    to: email,
    subject: "Verify your email",
    html: `<p>Verify your email address to complete the signup and login into your account.</p>
  <p>This link <b>expires in 6 hours</b>.</p>
  <p>Press <a href=${
    currentUrl + "user/verify/" + _id + "/" + uniqueString
  }>here</a> to proceed</p>`,
  };
  // hash the uniqueString
  const saltRounds = 10;
  bcrypt
    .hash(uniqueString, saltRounds)
    .then((hashedUniqueString) => {
      // set values in mailVerification collection
      const newMailVerification = new MailVerification({
        userId: _id,
        uniqueString: hashedUniqueString,
        createdAt: Date.now(),
        expiresAt: Date.now() + 21600000, // 6 hours in milliseconds
      });
      newMailVerification
        .save()
        .then(() => {
          sendMail(mailOptions)
            .then(() => {
              // email sent and verification record saved
              res.json({
                status: "Pending",
                message: "Verification email sent",
              });
            })
            .catch((error) => {
              console.log(error);
              res.json({
                status: "Failed",
                message: "Verification email failed",
              });
            });
        })
        .catch(() => {
          res.json({
            status: "Failed",
            message: "Couldn't save verification email data",
          });
        });
    })
    .catch(() => {
      res.json({
        status: "Failed",
        message: "An error occurred while hashing email data",
      });
    });
};

exports.signin = async (req, res) => {
  let { username, password } = req.body;
  if (utils.containsEmptyCredentials(req.body)) {
    res.json({
      status: "Failed",
      message: "Empty credentials supplied",
    });
  } else {
    try {
      await User.find({ username }).then((data) => {
        if (data.length) {
          // user exists
          // check is user email is verified
          if (!data[0].verified) {
            res.json({
              status: "Failed",
              message:
                "Email hasn't been verified yet. Please check your email",
              data: data,
            });
          } else if (data[0].username !== username) {
            res.json({
              status: "Failed",
              message: "Invalid User Name",
              data: data,
            });
          } else {
            const hashedPassword = data[0].password;
            bcrypt
              .compare(password, hashedPassword)
              .then((result) => {
                if (result) {
                  res.json({
                    status: "Success",
                    message: "Signin successful",
                    data: data,
                  });
                } else {
                  res.json({
                    status: "Failed",
                    message: "Invalid password entered",
                  });
                }
              })
              .catch((error) => {
                console.log(error);
                res.json({
                  status: "Failed",
                  message: "An error ocurred while comparing passwords",
                });
              });
          }
        } else {
          res.json({
            status: "Failed",
            message: "Invalid credentials",
          });
        }
      });
    } catch (error) {
      console.log(error);
      res.json({
        status: "Failed",
        message: "An error ocurred while checking for existing user",
      });
    }
  }
};

exports.sendResetPasswordEmail = async (req, res) => {
  const { email, redirectUrl } = req.body;

  // check if email exists
  User.find({ email })
    .then((data) => {
      if (data.length) {
        // user exists

        // check if the  user is verified
        if (!data[0].verified) {
          res.json({
            status: "Failed",
            message: "Email hasn't been verified yet, please check your email",
          });
        } else {
          // proceed with email to reset password
          sendResetEmail(data[0], redirectUrl, res);
        }
      } else {
        res.json({
          status: "Failed",
          message: "No account with the supplied email exists",
        });
      }
    })
    .catch((error) => {
      console.log(error);
      res.json({
        status: "Failed",
        message: "An error ocurred when checking for the existing user",
      });
    });
};

// send password reset email
const sendResetEmail = ({ _id, email }, redirectUrl, res) => {
  const resetString = uuidv4() + _id;
  PasswordReset.deleteMany({ userId: _id })
    .then(() => {
      const mailOptions = {
        from: process.env.AUTH_EMAIL,
        to: email,
        subject: "Patient Aide password reset",
        html: `<p>Please use the link below to reset your password</p>
      <p>This link <b>expires in 1 hour</b>.</p>
      <p>Press <a href=${
        redirectUrl + "/" + _id + "/" + resetString
      }>here</a> to proceed</p>`,
      };
      // hash the reset string
      const saltRounds = 10;
      bcrypt
        .hash(resetString, saltRounds)
        .then((hashedResetString) => {
          // set values in password reset collection
          const newPasswordReset = new PasswordReset({
            userId: _id,
            resetString: hashedResetString,
            createdAt: Date.now(),
            expiresAt: Date.now() + 3600000, // the reset link will be valid for 1 hour
          });

          newPasswordReset
            .save()
            .then(() => {
              sendMail(mailOptions)
                .then(() => {
                  // reset email sent and password reset record saved
                  res.json({
                    status: "Pending",
                    message: "Password reset email sent",
                  });
                })
                .catch((error) => {
                  console.log(error);
                  res.json({
                    status: "Failed",
                    message: "Password reset failed",
                  });
                });
            })
            .catch((error) => {
              console.log(error);
              res.json({
                status: "Failed",
                message: "Couldn't save the password reset data",
              });
            });
        })
        .catch((error) => {
          console.log(error);
          res.json({
            status: "Failed",
            message:
              "An error occurred while encrypting the password reset data",
          });
        });
    })
    .catch((error) => {
      console.log(error);
      res.json({
        status: "Failed",
        message: "Clearing existing password reset records have failed",
      });
    });
};

// the actual reset of the password
exports.resetPassword = (req, res) => {
  let { userId, resetString, newPassword } = req.body;

  PasswordReset.find({ userId })
    .then((result) => {
      if (result.length > 0) {
        // password reset record exists, we can proceed
        const { expiresAt } = result[0];
        const hashedResetString = result[0].resetString;

        // checking for expired reset string
        if (expiresAt < Date.now()) {
          PasswordReset.deleteOne({ userId })
            .then(() => {
              // reset record deleted successfully
              res.json({
                status: "Failed",
                message: "Password reset link have expired",
              });
            })
            .catch((error) => {
              // deletion failed
              console.log(error);
              res.json({
                status: "Failed",
                message: "Clearing password reset records have failed",
              });
            });
        } else {
          // valid reset record exists so we validate the reset string (sent via email)
          // compare the hashed reset string
          bcrypt
            .compare(resetString, hashedResetString)
            .then((result) => {
              if (result) {
                // string matched
                // hash password again

                const saltRounds = 10;
                bcrypt
                  .hash(newPassword, saltRounds)
                  .then((hashedNewPassword) => {
                    // update user password
                    User.updateOne(
                      { _id: userId },
                      { password: hashedNewPassword }
                    )
                      .then(() => {
                        // update completed, we can delete the reset record
                        PasswordReset.deleteOne({ userId })
                          .then(() => {
                            // both user record and reset record updated
                            res.json({
                              status: "Success",
                              message: "Password has been reset successfully",
                            });
                          })
                          .catch((error) => {
                            console.log(error);
                            res.json({
                              status: "Failed",
                              message:
                                "An error ocurred while finalizing the password reset",
                            });
                          });
                      })
                      .catch((error) => {
                        console.log(error);
                        res.json({
                          status: "Failed",
                          message: "Updating user password failed",
                        });
                      });
                  })
                  .catch((error) => {
                    console.log(error);
                    res.json({
                      status: "Failed",
                      message: "An error occurred while hashing new password",
                    });
                  });
              } else {
                // existing record but incorrect reset string passed
                res.json({
                  status: "Failed",
                  message: "Invalid password reset details passed",
                });
              }
            })
            .catch((error) => {
              console.log(error);
              res.json({
                status: "Failed",
                message: "Comparing password reset string failed",
              });
            });
        }
      } else {
        // password reset record does not exists
        res.json({
          status: "Failed",
          message: "Password reset request not found",
        });
      }
    })
    .catch((error) => {
      console.log(error);
      res.json({
        status: "Failed",
        message: "Checking for existing password record failed",
      });
    });
};

// util
const isVerified = (users) => {
  return users.some((user) => user.verified);
};

exports.updateNotification = (req, res) => {
  const { userId, notificationType, notificationId } = req.body;
  const objectToPush = {};
  objectToPush[notificationType] = [notificationId];

  User.updateOne({ _id: userId }, { $push: objectToPush }, (err, result) => {
    if (err) {
      res.send(err);
    } else {
      res.send(result);
    }
  });
};

exports.updateReminder = (req, res) => {
  const { userId, reminder } = req.body;

  User.findOneAndUpdate(
    { _id: userId },
    { reminder: reminder },

    { new: true },
    (err, result) => {
      if (err) {
        res.send(err);
      } else {
        res.send(result);
      }
    }
  );
};

exports.toggleValidicStatus = (req, res) => {
  const { uid, status } = req.body;

  User.updateOne({ _id: uid }, { validicAccess: status }, (err, result) => {
    if (err) {
      res.send({
        err: err,
        message: "error while updating validic status",
      });
    } else {
      res.send(result);
    }
  });
};
