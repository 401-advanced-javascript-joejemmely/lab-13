'use strict';

const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const SINGLE_USE_TOKENS = !!process.env.SINGLE_USE_TOKENS;
const TOKEN_LIFETIME = process.env.TOKEN_LIFETIME;
const SECRET = process.env.SECRET || 'this is unsafe';

const users = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  email: { type: String },
  role: { type: String, default: 'user', enum: ['admin', 'editor', 'user'] },
});

const usedTokens = new Set();

users.pre('save', function(next) {
  bcrypt
    .hash(this.password, 10)
    .then(hashedPassword => {
      this.password = hashedPassword;
      next();
    })
    .catch(console.error);
});

users.statics.createFromOauth = function(email) {
  if (!email) {
    return Promise.reject('Validation Error');
  }

  return this.findOne({ email })
    .then(user => {
      if (!user) {
        throw new Error('User Not Found');
      }
      console.log('Welcome Back', user.username);
      return user;
    })
    .catch(error => {
      console.log('Creating new user');
      let username = email;
      let password = 'none';
      return this.create({ username, password, email });
    });
};

users.statics.authenticateBasic = function(auth) {
  let query = { username: auth.username };
  return this.findOne(query)
    .then(user => user && user.comparePassword(auth.password))
    .catch(error => {
      throw error;
    });
};

users.statics.authenticateBearer = function(token) {
  if (usedTokens.has(token)) {
    return Promise.reject('Invalid Token');
  }
  try {
    const parsedToken = jwt.verify(token, SECRET);

    if (SINGLE_USE_TOKENS && parsedToken.type !== 'key') {
      usedTokens.add(token);
    }

    let query = { _id: parsedToken.id };
    return this.findOne(query);
  } catch (error) {
    return Promise.reject('Invalid Token');
  }
};

users.methods.comparePassword = function(password) {
  return bcrypt
    .compare(password, this.password)
    .then(valid => (valid ? this : null));
};

users.methods.generateToken = function(type) {
  const token = {
    id: this._id,
    role: this.role,
    type: type || 'user',
  };

  let options = {};
  if (type !== 'key' && !!TOKEN_LIFETIME) {
    options.expiresIn = TOKEN_LIFETIME;
  }

  return jwt.sign(token, SECRET, options);
};

users.methods.generateKey = function() {
  return this.generateToken('key');
};

module.exports = mongoose.model('users', users);
