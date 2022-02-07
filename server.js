'use strict';

require('dotenv').config();
const express = require('express');
const session = require('express-session');
const myDB = require('./connection');
const fccTesting = require('./freeCodeCamp/fcctesting.js');
const passport = require('passport');
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


app.route('/').get((req, res) => {
res.render('pug', {
    title: 'Connected to Database',
    message: 'Please login'
});
});

passport.serializeUser((user, done) => {
    done(null, user._id);
});

passport.deserializeUser((id, done) => {
    // myDB.findOne({ _id: new ObjectID(id) }, (err, doc) => {
        done(null, doc);
    // });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log('Listening on port ' + PORT);
});