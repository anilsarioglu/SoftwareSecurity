var express = require('express');
var router = express.Router();
var multer = require('multer');
var upload = multer({dest: './uploads'});
var passport = require('passport');
var randomstring = require("randomstring");
var LocalStrategy = require('passport-local').Strategy;
var pwnedPassword = require('hibp').pwnedPassword;

var User = require('../models/user');

/* GET users listing. */
router.get('/', function(req, res, next) {
  res.send('respond with a resource');
});

router.get('/register', function(req, res, next) {
  res.render('register',{title: 'Register'});
});

router.get('/login', function(req, res, next) {
  res.render('login', {title: 'Login'});
});

router.post('/login', passport.authenticate('local',{failureRedirect: '/users/login', failureFlash: 'Invalid username or password'}),
  function(req, res) {
   req.flash('success', 'You are now logged in');
   res.redirect('/');
});

passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.getUserById(id, function(err, user) {
    done(err, user);
  });
});

passport.use(new LocalStrategy(function(username, password, done){
  User.getUserByUsername(username.toLowerCase(), function(err, user){
    if(err) throw err;
    if(!user){
      return done(null, false, {message: 'Unknown User'});
    }

    User.comparePassword(password, user.password, function(err, isMatch){
      if(err) return done(err);
      if(isMatch){
        return done(null, user);
      } else {
        return done(null, false, {message:'Invalid Password'});
      }
    });
  });
}));

router.post('/register', upload.single('profileimage') ,function(req, res, next) {
  var name = req.body.name;
  var email = req.body.email;
  var username = req.body.username;
  var password = req.body.password;
  var password2 = req.body.password2;

  // Check if username exists
  var usernameLower = username.toLowerCase();
  if(User.getUserByUsername(usernameLower, function(err, user){
    if(err) throw err;
    if(user){
      console.log("User already exists");
      req.checkBody('usernameLower', 'Username already exists').equals(user)
    }
  }));

  // Generate random password
  function randomInt(low, high) {
    return Math.floor(Math.random() * (high - low) + low)
  }

  var pwlength = randomInt(6, 11);
  var pw = randomstring.generate({
    length: pwlength,
    charset: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789@$.!%*#?&'
  });

  // Check if password field is empty
  var isEmptyPw = false;

  if(!password){
    isEmptyPw = true;
    password = pw;
    password2 = pw;
  } else {
    req.checkBody('password','Password has to be minimum eight characters in length').isLength({min: 8})
    req.checkBody('password2','Passwords do not match').equals(req.body.password);
  }

  if(req.file){
  	console.log('Uploading File...');
  	var profileimage = req.file.filename;
  } else {
  	console.log('No File Uploaded...');
  	var profileimage = 'noimage.jpg';
  }

  // Form Validator
  req.checkBody('name','Name field is required').notEmpty();
  req.checkBody('email','Email field is required').notEmpty();
  req.checkBody('email','Email is not valid').isEmail();
  req.checkBody('username','Username field is required').notEmpty();

  var x = 0;
  
  function checkPwn(pwd, callback){
    pwnedPassword(pwd)
    .then(numPwns => {
    if (numPwns) {
      console.log('=======================> numpwns: ' + numPwns);
      x = numPwns;
      console.log('We are in checkPwn function');
      callback();
    } else {
      callback();
    }
    });
  }

  function check(){
    console.log('We are in check function');
    console.log('x = ' + x);
    if(x){
      // Generates a validation error
      req.checkBody('password','Please choose a stronger password').equals(req.body.name);
      var errors = req.validationErrors();

      if(errors){
        res.render('register', {
          errors: errors
        });
      }
    } else {
          // Check Errors
      var errors = req.validationErrors();


      if(errors){
        res.render('register', {
          errors: errors
        });
      } else {
        var newUser = new User({
          name: name,
          email: email,
          username: username.toLowerCase(),
          password: password,
          profileimage: profileimage
        });

        User.createUser(newUser, function(err, user){
          if(err) throw err;
          console.log(user);
        });

        if(isEmptyPw){
          req.flash('success', 'You are now registered and can login. Your password is: ' + password);
        } else {
          req.flash('success', 'You are now registered and can login.');
        }
        

        res.location('/');
        res.redirect('/');
      }
    }
  }

  checkPwn(password, check);
});

router.get('/logout', function(req, res){
  req.logout();
  req.flash('success', 'You are now logged out');
  res.redirect('/users/login');
});

module.exports = router;
