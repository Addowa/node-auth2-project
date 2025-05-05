const router = require("express").Router();
const { checkUsernameExists, validateRoleName } = require('./auth-middleware');
const { JWT_SECRET } = require("../secrets"); // use this secret!
const bcrypt = require('bcryptjs');
const Users = require('../users/users-model');

router.post("/register", validateRoleName, async (req, res, next) => {
  try {
    const { username, password } = req.body;
    const hash = bcrypt.hashSync(password, 8); 
    const newUser = await Users.add({
      username,
      password: hash,
      role_name: req.role_name, 
    });
    res.status(201).json(newUser);
  } catch (err) {
    next(err);
  }
});

const jwt = require('jsonwebtoken');

function buildToken(user) {
  const payload = {
    subject: user.user_id,
    username: user.username,
    role_name: user.role_name
  };
  const options = {
    expiresIn: '1d'
  };
  return jwt.sign(payload, JWT_SECRET, options);
}

router.post("/login", checkUsernameExists, async (req, res, next) => {
  try {
    const { password } = req.body;
    const user = req.userFromDb;

    if (bcrypt.compareSync(password, user.password)) {
      const token = buildToken(user);
      res.status(200).json({
        message: `${user.username} is back!`,
        token
      });
    } else {
      res.status(401).json({ message: "Invalid credentials" });
    }
  } catch (err) {
    next(err);
  }
});

module.exports = router;
