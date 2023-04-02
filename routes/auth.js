const express = require('express');
const { check, body } = require('express-validator/check');

const authController = require('../controllers/auth');
const User = require('../models/user');

const router = express.Router();

router.get('/login', authController.getLogin);

router.get('/signup', authController.getSignup);

router.post(
  '/login',
  [
    body('email', 'please enter a valid Email').isEmail().normalizeEmail(),
    body('password')
      .isLength({ min: 5 })
      .withMessage('Password too short')
      .isAlphanumeric()
      .withMessage('Password must have only numbers and letters')
      .trim(),
  ],
  authController.postLogin
);

router.post(
  '/signup',
  [
    // check -> everything -> body/ headers/ cookies
    check('email')
      .isEmail()
      .withMessage('Please enter a valid email.')
      .custom((value, { req }) => {
        // adding your own validator
        // if (value === 'test@test.com') {
        //   throw new Error('Email forbidden');
        // }
        // return true;
        return User.findOne({ email: value }).then((userDoc) => {
          if (userDoc) {
            // promise rejection will result in a thrown error?
            return Promise.reject(
              'Email ald exists, please pick a different one.'
            );
          }
        });
      })
      // sanitizing email -> making sure all lowercase + etc?
      .normalizeEmail(),
    body(
      'password',
      'please enter a password with only numbers and text of at least 5 characters'
    )
      .isLength({ min: 5 })
      .withMessage('')
      .isAlphanumeric()
      // sanitizing pw -> trim extra white space
      .trim(),
    body('confirmPassword')
      .custom((value, { req }) => {
        if (value !== req.body.password) {
          throw new Error('Passwords have to match!');
        }
        return true;
      })
      .trim(),
  ],

  authController.postSignup
);

router.post('/logout', authController.postLogout);

router.get('/reset', authController.getReset);

router.post('/reset', authController.postReset);

router.get('/reset/:token', authController.getNewPassword);

router.post('/new-password', authController.postNewPassword);

module.exports = router;
