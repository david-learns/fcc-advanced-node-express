'use strict';

require('dotenv').config();
const express = require('express');
const session = require('express-session');
const myDB = require('./connection');
const fccTesting = require('./freeCodeCamp/fcctesting.js');
const passport = require('passport');
const LocalStrategy = require('passport-local');
const ObjectID = require('mongodb').ObjectID;


const app = express();


fccTesting(app); //For FCC testing purposes
app.use('/public', express.static(process.cwd() + '/public'));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: true,
  saveUninitialized: true,
  cookie: { secure: false }
}));
app.use(passport.initialize());
app.use(passport.session());


// set views directory and view engine
app.set('views', './views');
app.set('view engine', 'pug');


myDB(async client => {

  const myDatabase = await client.db().collection('users');

  passport.use(new LocalStrategy(
    function (username, password, done) {
      myDatabase.findOne({ username: username }, function (err, user) {
        console.log('User '+ username +' attempted to log in.');
        if (err) { return done(err) }
        if (!user) { return done(null, false) }
        if (password !== user.password) { return done(null, false) }
        return done(null, user);
      });
    }
  ));

  app.route('/').get((req, res) => {
    res.render('pug', {
      showLogin: true,
      title: 'Connected to Database',
      message: 'Please login'
    });
  });

  const loginOptions = {
    failureRedirect: '/'
  }

  app.route('/login').post(passport.authenticate('local', loginOptions), (req, res) => {
    res.redirect('/profile');
  });

  app.route('/profile').get((req, res) => {
    res.render('pug/profile');
  })

  passport.serializeUser((user, done) => {
    done(null, user._id);
  });

  passport.deserializeUser((id, done) => {
    myDB.findOne({ _id: new ObjectID(id) }, (err, doc) => {
      done(null, doc);
    });
  });


}).catch(e => {

  app.route('/').get((req, res) => {
    res.render('pug', {
      title: e,
      message: 'Unable to login'
    });
  });

});


const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log('Listening on port ' + PORT);
});
