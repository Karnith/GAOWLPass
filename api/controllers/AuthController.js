/**
 * AuthController
 *
 * @module      :: Controller
 * @description	:: Provides the base authentication
 *                 actions used to make waterlock work.
 *
 * @docs        :: http://waterlock.ninja/documentation
 */
var passport = require('passport');
module.exports = require('waterlock').waterlocked({
    // http://developer.github.com/v3/
    // http://developer.github.com/v3/oauth/#scopes
    github: function (req, res) {
        passport.authenticate('github', { failureRedirect: '/' },
            function (err, user) {
                // sails.log.warn("User "+user.name+" username:("+user.username+") is attempting to log in.");
                req.logIn(user, function (err) {
                    if (err) {
                        sails.log.error(err);
                        res.view('500');
                        return;
                    }

                    // Log user in
                    req.session.authenticated = true;
                    req.session.user = user;

                    if (req.session.user.admin) {
                        res.redirect('/user');
                        return;
                    }
                    waterlock.logger.debug('user login success');
                    res.redirect('/user/show/' + user.id);
                });
            })(req, res);
    },

    // https://developers.facebook.com/docs/
    facebook: function (req, res) {
        passport.authenticate('facebook', { failureRedirect: '/', scope: ['email'] },
            function (err, user) {
                // sails.log.warn("User "+user.name+" username:("+user.username+") is attempting to log in.");
                req.logIn(user, function (err) {
                    if (err) {
                        sails.log.error(err);
                        res.view('500');
                        return;
                    }

                    // Log user in
                    req.session.authenticated = true;
                    req.session.user = user;

                    if (req.session.user.admin) {
                        res.redirect('/user');
                        return;
                    }
                    waterlock.logger.debug('user login success');
                    res.redirect('/user/show/' + user.id);
                });
            })(req, res);
    },

    // https://developers.google.com/
    // https://developers.google.com/accounts/docs/OAuth2Login#scope-param
    google: function (req, res) {
        passport.authenticate('google', { failureRedirect: '/', scope:['https://www.googleapis.com/auth/plus.login','https://www.googleapis.com/auth/userinfo.profile','https://www.googleapis.com/auth/userinfo.email'] },
            function (err, user) {
                // sails.log.warn("User "+user.name+" username:("+user.username+") is attempting to log in.");
                req.logIn(user, function (err) {
                    if (err) {
                        sails.log.error(err);
                        res.view('500');
                        return;
                    }

                    // Log user in
                    req.session.authenticated = true;
                    req.session.user = user;

                    if (req.session.user.admin) {
                        res.redirect('/user');
                        return;
                    }
                    waterlock.logger.debug('user login success');
                    res.redirect('/user/show/' + user.id);
                });
            })(req, res);
    },

    ldap: function (req, res) {
        passport.authenticate('ldapauth', { failureRedirect: '/'},
            function (err, user) {
                // sails.log.warn("User "+user.name+" username:("+user.username+") is attempting to log in.");
                req.logIn(user, function (err) {
                    if (err) {
                        sails.log.error(err);
                        res.view('500');
                        return;
                    }

                    // Log user in
                    req.session.authenticated = true;
                    req.session.user = user;

                    if (req.session.user.admin) {
                        res.redirect('/user');
                        return;
                    }
                    waterlock.logger.debug('user login success');
                    res.redirect('/user/show/' + user.id);
                });
            })(req, res);
    }
});