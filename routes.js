'use strict';

const bcrypt = require('bcrypt');
const passport = require('passport');


const loginOptions = {
    failureRedirect: '/'
};



module.exports = function (app, myDatabase) {

    app.route('/').get((req, res) => {
        res.render('pug', {
            showLogin: true,
            showRegistration: true,
            showSocialAuth: true,
            title: 'Connected to Database',
            message: 'Please login'
        });
    });

    app.route('/register').post((req, res, next) => {
        myDatabase.findOne({ username: req.body.username }, function (err, user) {
            if (err) {
                next(err);
            } else if (user) {
                res.redirect('/');
            } else {
                const hash = bcrypt.hashSync(req.body.password, 12);
                const userCreds = {
                    username: req.body.username,
                    password: hash
                };
                myDatabase.insertOne(userCreds, (err, doc) => {
                    if (err) {
                        res.redirect('/');
                    } else {
                        next(null, doc.ops[0]);
                    }
                });
            }
        });
    },
        passport.authenticate('local', loginOptions),
        (req, res, next) => {
            res.redirect('pug/profile');
        }
    );

    app.route('/login').post(passport.authenticate('local', loginOptions), (req, res) => {
        res.redirect('pug/profile');
    });

    app.route('/profile').get(ensureAuthenticated, (req, res) => {
        res.render('pug/profile', {
            username: req.user.username
        });
    });

    app.route('/logout').get((req, res) => {
        req.logout();
        res.redirect('/');
    });

    app.route('/auth/github/callback').get(passport.authenticate('github', loginOptions), (req, res) => {
        req.session.user_id = req.user.id;
        res.redirect('pug/chat');
    });

    app.route('/auth/github').get(passport.authenticate('github'));

    app.route('/chat').get(ensureAuthenticated, (req, res) => {
        res.render('pug/chat', {
            user: req.user
        });
    });

    app.use((req, res, next) => {
        res.status(404)
            .type('text')
            .send('Not Found');
    });
    
}


function ensureAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
        return next();
    }
    res.redirect('/');
}