const express = require("express");
const usersRepo = require("../../repositories/users");
const signupTemplate = require("../../views/admin/auth/signup");
const signinTemplate = require("../../views/admin/auth/signin");
const {
  requireEmail,
  requirePassword,
  requirePasswordConfirmation,
  requireEmailExists,
  requirePasswordValid,
} = require("./validators");
const { handleErrors } = require("./middlewares");

const router = express.Router();

router.get("/admin/signup", (req, res) => {
  res.send(signupTemplate({ req }));
});

router.post(
  "/admin/signup",
  [requireEmail, requirePassword, requirePasswordConfirmation],
  handleErrors(signupTemplate),
  async (req, res) => {
    const { email, password } = req.body;

    // create a user in our user repo to represent this person
    const user = await usersRepo.create({ email, password });

    // Store the id of that user inside the user's cookie
    // req.session === {   } // added by cookie session!
    req.session.userId = user.id;

    res.redirect("/admin/products");
  }
);

router.get("/admin/signout", (req, res) => {
  req.session = null;
  res.redirect("/admin/signin");
});
router.get("/admin/signin", (req, res) => {
  res.send(signinTemplate({}));
});

router.post(
  "/admin/signin",
  [requireEmailExists, requirePasswordValid],
  handleErrors(signinTemplate),
  async (req, res) => {
    const { email } = req.body;
    const user = await usersRepo.getOneBy({ email });

    req.session.userId = user.id;

    res.redirect("/admin/products");
  }
);

module.exports = router;
