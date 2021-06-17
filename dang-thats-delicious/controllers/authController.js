const passport = require("passport");
const crypto = require("crypto");
const mongoose = require("mongoose");
const promisify = require("es6-promisify");
const User = mongoose.model("User");
const mail = require("../handlers/mail");

exports.login = passport.authenticate("local", {
  failureRedirect: "/login",
  failureFlash: "Failed Login!",
  successRedirect: "/",
  successFlash: "You have now logged in",
});

exports.logout = (req, res) => {
  req.logout();
  req.flash("success", "You are now logged out!");
  res.redirect("/");
};

exports.isLoggedIn = (req, res, next) => {
  //first check if the user is authenticated
  if (req.isAuthenticated()) {
    next(); //carry on! they are logged in!
    return;
  }

  req.flash("error", "You must be logged in to add a store");
  res.redirect("/login");
};

exports.forgot = async (req, res) => {
  // 1. See if user with that email exists
  const user = await User.findOne({ email: req.body.email });
  // if (!user) {
  //   req.flash(
  //     "error",
  //     "A password reset has been mailed to you if the email exists"
  //   );
  //   return res.redirect("/login");
  // }
  //2. Set reset tokens and expiry on their account
  user.resetPasswordToken = crypto.randomBytes(20).toString("hex");
  user.resetPasswordExpires = Date.now() + 360000; //1 hour from now
  await user.save();
  //3. Send them an email with the token
  const resetURL = `http://${req.headers.host}/account/reset/${user.resetPasswordToken}`;
  await mail.send({
    user,
    subject: "Password reset",
    resetURL,
    filename: "password-reset",
  });
  req.flash(
    "success",
    `You have been emailed a password reset link if your email exists on the system.`
  );
  //4. Redirect to login page
  res.redirect("/login");
};

exports.reset = async (req, res) => {
  const user = await User.findOne({
    resetPasswordToken: req.params.token,
    resetPasswordExpires: { $gt: Date.now() },
  });

  if (!user) {
    req.flash("error", "Password reset is invalid or expired");
    return res.redirect("/login");
  }

  //if there is a user, show the reset password form
  res.render("reset", { title: "Reset your password" });
};

exports.confirmedPasswords = (req, res, next) => {
  if (req.body.password === req.body["confirm-password"]) {
    next();
    return;
  }
  req.flash("error", "Passwords do not match");
  res.redirect("back");
};

exports.update = async (req, res) => {
  const user = await User.findOne({
    resetPasswordToken: req.params.token,
    resetPasswordExpires: { $gt: Date.now() },
  });

  if (!user) {
    req.flash("error", "Password reset is invalid or expired");
    return res.redirect("/login");
  }

  const setPassword = promisify(user.setPassword, user);

  await setPassword(req.body.password);

  user.resetPasswordToken = undefined;
  user.resetPasswordExpires = undefined;
  const updatedUser = await user.save();
  await req.login(updatedUser);
  req.flash(
    "success",
    "Nice! Your password has been reset! You are now logged in"
  );
  res.redirect("/");
};
