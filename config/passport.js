var passport = require('passport')
    , GitHubStrategy = require('passport-github').Strategy
    , FacebookStrategy = require('passport-facebook').Strategy
    , GoogleStrategy = require('passport-google-oauth').OAuth2Strategy;
// , LdapStrategy = require('passport-ldapauth').Strategy;

// surround sails logging into a custom function
function sailsLog(option, log) {
    'use strict';
    switch (option) {
        case 'info':
            sails.log.info(log);
            break;
        case 'warn':
            sails.log.warn(log);
            break;
        case 'err':
            sails.log.error(log);
            break;
    }
}

var verifyHandler = function (token, tokenSecret, profile, done) {
    process.nextTick(function () {
        sailsLog('info', "Getting User Profile...");
        // sails.log.warn(profile);
        User.findOne({
                or: [
                    {uid: parseInt(profile.id)},
                    {uid: profile.id}
                ]
            }
        )
        .populate('auth')
        .exec(function (err, userLoggingIn) {
                sailsLog('info', "Checking if user already exists in database....");
                if (userLoggingIn) {
                    sailsLog('info', "User "+userLoggingIn.name+" found.");

                    userLoggingIn.online = true;
                    userLoggingIn.save(function(err, userLoggingIn) {
                        if(err) {
                            waterlock.logger.debug(err);
                            return next(err);
                        }

                        User.publishUpdate(userLoggingIn.id, {
                            loggedIn: true,
                            id: userLoggingIn.id,
                            name: userLoggingIn.name,
                            action: ' has logged in.'
                        });

                        waterlock.logger.debug('user login success');
                        return done(null, userLoggingIn);
                    });

                } else {
                    sailsLog('warn', "User not found, creating user profile....");
                    var data = {
                            provider: profile.provider,
                            uid: profile.id,
                            name: profile.displayName,
                            username: profile.username
                        };
                        //userEmail = {}; -- for later use when slugs are added

                    if(profile.emails && profile.emails[0] && profile.emails[0].value) {
                        data.email = profile.emails[0].value;
                    }
                    if(!profile.displayName) {
                        data.name = profile.username;
                    }
                    else {
                        if(profile.name && profile.name.givenName) {
                            data.firstname = profile.name.givenName;
                        }
                        if(profile.name && profile.name.familyName) {
                            data.lastname = profile.name.familyName;
                        }
                    }
                    if (!profile.username) {
                        sailsLog('info', "User "+profile.displayName+" profile has been created.");
                    }
                    else{
                        sailsLog('info', "User "+profile.displayName+" ("+profile.username+") profile has been created.");
                    }

                    User.create(data).exec(function (err, user) {
                        if (err){
                            waterlock.logger.debug(err);
                            return done(err);
                         }

                        waterlock.engine.attachAuthToUser(data, user, function (err) {
                            if (err) {
                                waterlock.logger.debug(err);
                                return done(err);
                            }

                            //user.email = userEmail.email;

                            user.online = true;
                            user.save(function(err, user) {
                                if(err) {
                                    waterlock.logger.debug(err);
                                    return next(err);
                                }
                                user.action = " signed-up and logged-in.";

                                User.publishCreate(user);
                            });

                            waterlock.logger.debug('user login success');
                            return done(err, user);
                        });
                    });
                }
            });
    });
};

passport.serializeUser(function (user, done) {
    done(null, user.uid);
});

passport.deserializeUser(function (uid, done) {
    User.findOne({uid: uid}).exec(function (err, user) {
        done(err, user)
    });
});


module.exports = {

    // Init custom express middleware
    http: {
        customMiddleware: function (app) {

            passport.use(new GitHubStrategy({
                    clientID: "app id",
                    clientSecret: "app secret",
                    callbackURL: "http://localhost/auth/github/callback"
                },
                verifyHandler
            ));

            passport.use(new FacebookStrategy({
                    clientID: "app id",
                    clientSecret: "app secret",
                    callbackURL: "http://localhost/auth/facebook/callback"

                },
                verifyHandler
            ));

            passport.use(new GoogleStrategy({
                    clientID: 'app id',
                    clientSecret: 'app secret',
                    callbackURL: 'http://localhost/auth/google/callback'
                },
                verifyHandler
            ));

            // passport.use(new LdapStrategy({
            // server: {
            // url: 'ldap://ldap.domain.com',
            // adminDn: '',
            // adminPassword: '',
            // searchBase: 'dc=, dc=',
            // searchFilter: '(&(objectcategory=person)(objectclass=user)(|(samaccountname={{username}})(mail={{username}})))',
            // searchAttributes: ['displayName', 'mail']
            // }
            // },
            // verifyHandler
            // ));

            app.use(passport.initialize());
            app.use(passport.session());
        }
    }

};