const express = require("express");
const userController = require("../controllers/user");

const MailVerification = require("../models/MailVerification");
const User = require("../models/User");

const router = express.Router();
const path = require("path");
const bcrypt = require("bcrypt");

router.post("/signin", userController.signin);
router.post("/requestPasswordReset", userController.sendResetPasswordEmail);
router.post("/resetPassword", userController.resetPassword);
router.post("/careContacts", userController.updateCareContacts)
router.post("/careContacts/retrieveContacts", userController.getCareContacts)


router.put("/careContacts", userController.deleteCareContact)
router.put("/updateNotification", userController.updateNotification);
router.put("/updateValidicStatus", userController.toggleValidicStatus);
router.put("/updateCredentials", userController.updateCredentials);
router.put("/signup", userController.signup);
router.put("/updateReminder", userController.updateReminder);

router.get("/checkUserData", userController.checkUserData);
router.get("/verify/:userId/:uniqueString", (req, res) => {
  let { userId, uniqueString } = req.params;
  MailVerification.find({ userId })
    .then((result) => {
      if (result.length > 0) {
        // user verification record exists, so, we proceed
        const { expiresAt } = result[0];
        const hashedUniqueString = result[0].uniqueString;
        // checking for expired unique string
        if (expiresAt < Date.now()) {
          MailVerification.deleteOne({ userId })
            .then(() => {
              User.deleteOne({ _id: userId })
                .then(() => {
                  let message = "Link has expired, please Sign in again";
                  res.redirect(
                    `/user/verified/??error=true&message=${message}`
                  );
                })
                .catch((error) => {
                  console.log(error);
                  let message =
                    "An error occurred while clearing user with expired unique string";
                  res.redirect(
                    `/user/verified/??error=true&message=${message}`
                  );
                });
            })
            .catch((error) => {
              console.log(error);
              let message =
                "An error occurred while clearing expired user verification record";
              res.redirect(`/user/verified/??error=true&message=${message}`);
            });
        } else {
          // valid record exists so we validate the user string
          // first compare the hashes unique string
          bcrypt
            .compare(uniqueString, hashedUniqueString)
            .then((result) => {
              if (result) {
                // string match
                User.updateOne({ _id: userId }, { verified: true })
                  .then(() => {
                    MailVerification.deleteOne({ userId })
                      .then(() => {
                        res.sendFile(
                          path.join(__dirname, "./../views/verified.html")
                        );
                      })
                      .catch((error) => {
                        console.log(error);
                        let message =
                          "An error occurred while finalizing successful verification";
                        req.redirect(
                          `/user/verified/?error=true&message=${message}`
                        );
                      });
                  })
                  .catch((error) => {
                    console.log(error);
                    let message =
                      "An error occurred while updating user record to show verified";
                    req.redirect(
                      `/user/verified/?error=true&message=${message}`
                    );
                  });
              } else {
                let message =
                  "Invalid verification details passed. Please check your inbox";
                req.redirect(`/user/verified/?error=true&message=${message}`);
              }
            })
            .catch((error) => {
              console.log(error);
              let message =
                "An error occurred while checking for existing user verification record";
              req.redirect(`/user/verified/?error=true&message=${message}`);
            });
        }
      } else {
        // user verification record doesn't exists
        let message =
          "Account record doesn't exists or has been already verified. Please sign in.";
        res.redirect(`/user/verified/?error=true&message=${message}`);
      }
    })
    .catch((error) => {
      console.log(error);
      let message =
        "An error occurred while checking for existing user verification record";
      req.redirect(`/user/verified/?error=true&message=${message}`);
    });
});
router.get("/verified", (req, res) => {
  res.sendFile(path.join(__dirname, "./../views/verified.html"));
});


module.exports = router;
