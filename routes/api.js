const express = require('express');
const crypto = require('crypto');
const mongoose = require('mongoose');

const UserDao = require('../models/user');
const SessionDao = require('../models/session');

var router = express.Router();

/**
 * Sha256 hash function
 * @param {*} data The data needed hash.
 * @return {string} Hashed result.
 */
const sha256Hash = function(data) {
  let hash = crypto.createHash('sha256');
  hash.update(data);
  return hash.digest('hex');
}

/**
 * Session id generator
 * @retuen {string} session id.
 */
const gensessionKey = function() {
  return sha256Hash(Date.now().toString());
}

/**
 * A Interceptor to check user is logged-in or not before.
 */
const checkLoginInterceptor = async(req, res, next) => {
  let sessionKey = req.get('Session-Key');
  if (!sessionKey) {
    res.sendStatus(401);
    console.log("Session key not exist!");
    return;
  }
  
  let session = await SessionDao.findOne({sessionKey: sessionKey}).exec();
  if (!session) {
    console.log("Session key is expired or non-recognized!");
    res.sendStatus(401);
    return;
  }
  req.params.userId = session.userId;
  next();
}

/**
 * @swagger
 * definitions:
 *   NewUser:
 *     type: object
 *     required:
 *       - name
 *       - email
 *       - password
 *     properties:
 *       name:
 *         type: string
 *       email:
 *         type: string
 *         format: email
 *       password:
 *         type: string
 *         format: password
 *   ModifyUser:
 *     type: object
 *     properties:
 *       name:
 *         type: string
 *       email:
 *         type: string
 *         format: email
 *       password:
 *         type: string
 *         format: password
 *   LoginForm:
 *     type: object
 *     required:
 *       - email
 *       - password
 *     properties:
 *       email:
 *         type: string
 *         format: email
 *       password:
 *         type: string
 *         format: password
 *   LoginResponse:
 *     type: object
 *     properties:
 *       session_key:
 *         type: string
 *   UserInfo:
 *     type: object
 *     properties:
 *       name:
 *         type: string
 *       email:
 *         type: string
 *         format: email
 *       update_at:
 *         type: string
 *         format: date-time
 * securityDefinitions:
 *   Session-Key:
 *     description: This session key will get after login, and expired after logout.
 *     type: apiKey
 *     name: Session-Key
 *     in: header
 */

/**
 * @swagger
 * /register:
 *   post:
 *     summary: register new user
 *     description: register new user
 *     consumes:
 *       - application/json
 *     produces:
 *       - text/plain
 *     parameters:
 *       - name: body
 *         description: new user object
 *         in: body
 *         required: true
 *         type: string
 *         schema:
 *           $ref: '#/definitions/NewUser'
 *     responses:
 *       200:
 *         description: user register successful.
 *       400:
 *         description: user info not complete.
 *       409:
 *         description: email is used.
 */
router.post('/register', async(req, res) => {
  let name = req.body.name;
  let email = req.body.email;
  let password = req.body.password;
  if (!name || !email || !password) {
    res.sendStatus(400);
    return;
  }

  let user = await UserDao.findOne({email: email}).exec();
  if (user) {
    console.log("User already exist!");
    res.sendStatus(409);
    return;
  }

  user = await UserDao.create({
    name: name,
    email: email,
    password: sha256Hash(password)
  });
  console.log("User created: " + user);
  res.sendStatus(200);
});

/**
 * @swagger
 * /login:
 *   post:
 *     summary: user login
 *     description: user login
 *     consumes:
 *       - application/json
 *     produces:
 *       - application/json
 *     parameters:
 *       - name: body
 *         description: login form
 *         in: body
 *         required: true
 *         type: string
 *         schema:
 *           $ref: '#/definitions/LoginForm'
 *     responses:
 *       200:
 *         description: login successful.
 *         schema:
 *           $ref: '#/definitions/LoginResponse'
 *       400:
 *         description: login form not complete.
 *       404:
 *         description: email and/or incorrect.
 */
router.post('/login', async(req, res) => {
  let email = req.body.email;
  let password = req.body.password;
  if (!email || !password) {
    res.sendStatus(400);
    return;
  }

  let user = await UserDao.findOne({email: email, password: sha256Hash(password)}).exec();
  if (!user) {
    res.sendStatus(404);
    return;
  }

  let session = await SessionDao.create({
    sessionKey: gensessionKey(),
    userId: user._id
  });
  console.log("User logged-in. Session: " + session);
  res.status(200).send({"session_key": session.sessionKey});
});

/**
 * @swagger
 * /logout:
 *   post:
 *     summary: user logout
 *     description: user logout
 *     produces:
 *       - text/plain
 *     responses:
 *       200:
 *         description: logout successful.
 *     security:
 *       - Session-Key: []
 */
router.post('/logout', async(req, res) => {
  let sessionKey = req.get('Session-Key');
  if (sessionKey) {
    await SessionDao.findOneAndRemove({sessionKey: sessionKey}).exec();
  }
  res.sendStatus(200);
});


/**
 * @swagger
 * /user:
 *   get:
 *     summary: get user info
 *     description: get user info
 *     produces:
 *       - application/json
 *     responses:
 *       200:
 *         description: logout successful.
 *         schema:
 *           $ref: '#/definitions/UserInfo'
 *       401:
 *         description: session expired or user not login yet.
 *     security:
 *       - Session-Key: []
 */
router.get('/user', checkLoginInterceptor, async(req, res) => {
  let user = await UserDao.findById(req.params.userId).exec();
  if (!user) {
    console.log("User is not exist!");
    res.sendStatus(401);
    return;
  }
  res.status(200).send({
    "name": user.name,
    "email": user.email,
    "update_at": user.updateAt.toLocaleString()
  });
});

/**
 * @swagger
 * /user:
 *   patch:
 *     summary: modify user info
 *     description: modify user info
 *     consumes:
 *       - application/json
 *     produces:
 *       - text/plain
 *     parameters:
 *       - name: body
 *         description: new user object
 *         in: body
 *         required: true
 *         type: string
 *         schema:
 *           $ref: '#/definitions/ModifyUser'
 *     responses:
 *       200:
 *         description: logout successful.
 *       400:
 *         description: session expired or user not login yet.
 *       401:
 *         description: body is empty.
 *       409:
 *         description: new email is used.
 *     security:
 *       - Session-Key: []
 */
router.patch('/user', checkLoginInterceptor, async(req, res) => {
  let user = await UserDao.findById(req.params.userId).exec();
  if (!user) {
    console.log("User is not exist!");
    res.sendStatus(401);
    return;
  }
  if(!req.body || Object.keys(req.body) < 1) {
    res.sendStatus(400);
    return;
  }

  let isUpdate = false;
  if (req.body.email && user.email != req.body.email) {
    let otherUser = await UserDao.findOne({email: req.body.email}).exec();
    if (otherUser) {
      console.log("Desired to modify email but it's used!");
      res.sendStatus(409);
      return;
    }
    user.email = req.body.email;
    isUpdate = true;
  }
  if (req.body.name) {
    user.name = req.body.name;
    isUpdate = true;
  }
  if (req.body.password) {
    user.password = sha256Hash(req.body.password);
    isUpdate = true;
  }
  if (isUpdate) {
    user.updateAt = new Date();
    await user.save();
  }
  res.sendStatus(200);
});

module.exports = router;
