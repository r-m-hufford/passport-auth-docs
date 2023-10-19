const express = require('express');
const passport = require('passport');
const gs = require('./utils/google-strategy');
const ls = require('./utils/local-strategy');
const crypto = require('crypto');
const db = require('../db');
const router = express.Router();

passport.use(gs);
passport.use(ls);

passport.serializeUser(function(user, cb) {
  process.nextTick(function() {
    cb(null, { id: user.id, username: user.username, name:user.name ? user.name : user.username });
  });
});

passport.deserializeUser(function(user, cb) {
  process.nextTick(function() {
    return cb(null, user);
  })
})

router.get('/login', (req, res, next) => {
  res.render('login');
})
// GOOGLE LOGIN
router.get('/login/federated/google', passport.authenticate('google'));

router.get('/oauth2/redirect/google', passport.authenticate('google', {
  successRedirect: '/',
  failureRedirect: '/login'
}));

router.post('/logout', (req, res, next) => {
  req.logOut(function(err) {
    if (err) { return next(err) }
    res.redirect('/');
  })
})

// CREDENTIAL LOGIN
router.post('/login/password', passport.authenticate('local', {
  successRedirect: '/',
  failureRedirect: '/login'
}));

router.post('/logout', (req, res, next) => {
  req.logOut(function(err) {
    if (err) { return next(err) };
    res.redirect('/');
  })
});


router.get('/signup', (req, res, next) => {
  res.render('signup');
});

router.post('/signup', (req, res, next) => {
  var salt = crypto.randomBytes(16);
  crypto.pbkdf2(req.body.password, salt, 310000, 32, 'sha256', function(err, hashedPassword) {
    if (err) { return next(err); }
    db.run('INSERT INTO users (username, hashed_password, salt) VALUES (?, ?, ?)', [
      req.body.username,
      hashedPassword,
      salt
    ], function(err) {
      if (err) { return next(err); }
      const user = {
        id: this.lastID,
        username: req.body.username
      };

      req.login(user, function(err) {
        if (err) { return next(err); }
        res.redirect('/');
      })
    })
  })
});

module.exports = router;