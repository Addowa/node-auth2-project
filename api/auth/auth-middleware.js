const jwt = require('jsonwebtoken');
const { JWT_SECRET } = require("../secrets"); // use this secret!
const Users = require('../users/users-model');

const restricted = (req, res, next) => {
  const token = req.headers.authorization;
  if (!token) {
    return res.status(401).json({ message: "Token required" });
  }

  jwt.verify(token, JWT_SECRET, (err, decodedToken) => {
    if (err) {
      return res.status(401).json({ message: "Token invalid" });
    }
    req.decodedJwt = decodedToken; 
    next();
  });
}

const only = role_name => (req, res, next) => {
  if (!req.decodedJwt || req.decodedJwt.role_name !== role_name) {
    return res.status(403).json({ message: "This is not for you" });
  }
  next();
}


const checkUsernameExists = async (req, res, next) => {
  const { username } = req.body;
  const [user] = await Users.findBy({ username });
  if (!user) {
    return res.status(401).json({ message: "Invalid credentials" });
  }
  req.userFromDb = user; 
  next();
}


const validateRoleName = (req, res, next) => {
  let { role_name } = req.body;

  if (!role_name || typeof role_name !== 'string' || role_name.trim() === '') {
    req.role_name = 'student';
    return next();
  }

  role_name = role_name.trim();

  if (role_name === 'admin') {
    return res.status(422).json({ message: "Role name can not be admin" });
  }

  if (role_name.length > 32) {
    return res.status(422).json({ message: "Role name can not be longer than 32 chars" });
  }

  req.role_name = role_name;
  next();
}

module.exports = {
  restricted,
  checkUsernameExists,
  validateRoleName,
  only,
}
