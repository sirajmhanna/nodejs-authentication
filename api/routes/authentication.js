const express = require("express");
const route = express.Router();
const AuthenticationControllers = require("../controllers/authentication");

// Login Route
route.post("/login", AuthenticationControllers.login);

// Logout Route
route.post("/logout", AuthenticationControllers.logout);

// Change Password Route
route.patch("/password/change", AuthenticationControllers.changePassword);

// Request Reset Password Route
route.get("/password/reset", AuthenticationControllers.requestResetPassword);

// Confirm Reset Password Route
route.patch(
  "/password/reset/confirm",
  AuthenticationControllers.confirmResetPassword
);

module.exports = route;
