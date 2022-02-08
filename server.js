'use strict';

require('dotenv').config();
const express = require('express');
const session = require('express-session');
const myDB = require('./connection');
const fccTesting = require('./freeCodeCamp/fcctesting.js');
const passport = require('passport');



const routes = require('./routes.js');
const auth = require('./auth.js');



const app = express();
const http = require('http').createServer(app);
const io = require('socket.io')(http);



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

  routes(app, myDatabase);
  auth(myDatabase);

  io.on('connection', socket => {
    console.log('A user has connected');
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
http.listen(PORT, () => {
  console.log('Listening on port ' + PORT);
});
