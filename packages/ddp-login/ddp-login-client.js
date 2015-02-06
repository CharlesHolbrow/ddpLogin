DDPLogin = {};

// wrapConnection adds Meteor's client side accounts-password login
// process to arbitrary connections

DDPLogin.connect = function(){
  var connection = DDP.connect.apply(DDP, arguments);
  var Accounts = {connection:connection};
  var Meteor = {};
  connection._wrappedContent = {
    Accounts:Accounts,
    Meteor:Meteor
  };

////////////////////////////////////////////////////////////////
//
//
//
// Stub functionality from accounts-base/localstorage_token.js
//
//
//
////////////////////////////////////////////////////////////////

  Meteor.loginWithToken = function (token, callback) {
    Accounts.callLoginMethod({
      methodArguments: [{resume: token}],
      userCallback: callback
    });
  };

  var psuedoLocalStore = {
    loginToken: undefined,
    loginTokenExpires: undefined,
    userId: undefined,
  }
  var storedLoginToken = function(){
    return psuedoLocalStore.loginToken;
  };
  var storedLoginTokenExpires = function(){
    return psuedoLocalStore.loginTokenExpires;
  };
  var unstoreLoginToken = function(){
    psuedoLocalStore.loginToken = undefined;
    psuedoLocalStore.loginTokenExpires = undefined;
    psuedoLocalStore.userId = undefined;
  };
  var storeLoginToken = function(userId, token, tokenExpires){
    psuedoLocalStore.loginToken = token;
    psuedoLocalStore.loginTokenExpires = tokenExpires;
    psuedoLocalStore.userId = userId;
  };

////////////////////////////////////////////////////////////////
//
//
//
// Add basic functionality from accounts-base accounts_common.js
//
//
//
////////////////////////////////////////////////////////////////

  Accounts._options = {};

  // how long (in days) until a login token expires
  var DEFAULT_LOGIN_EXPIRATION_DAYS = 90;
  // Clients don't try to auto-login with a token that is going to expire within
  // .1 * DEFAULT_LOGIN_EXPIRATION_DAYS, capped at MIN_TOKEN_LIFETIME_CAP_SECS.
  // Tries to avoid abrupt disconnects from expiring tokens.
  var MIN_TOKEN_LIFETIME_CAP_SECS = 3600; // one hour

  var getTokenLifetimeMs = function () {
    return (Accounts._options.loginExpirationInDays ||
            DEFAULT_LOGIN_EXPIRATION_DAYS) * 24 * 60 * 60 * 1000;
  };

  Accounts._tokenExpiration = function (when) {
    // We pass when through the Date constructor for backwards compatibility;
    // `when` used to be a number.
    return new Date((new Date(when)).getTime() + getTokenLifetimeMs());
  };

  Accounts._tokenExpiresSoon = function (when) {
    var minLifetimeMs = .1 * getTokenLifetimeMs();
    var minLifetimeCapMs = MIN_TOKEN_LIFETIME_CAP_SECS * 1000;
    if (minLifetimeMs > minLifetimeCapMs)
      minLifetimeMs = minLifetimeCapMs;
    return new Date() > (new Date(when) - minLifetimeMs);
  };

////////////////////////////////////////////////////////////////
//
//
//
// Add basic functionality from the accounts-base client
//
//
//
////////////////////////////////////////////////////////////////
  var loggingIn = false;
  var loggingInDeps = new Tracker.Dependency;

  // This is mostly just called within this file, but Meteor.loginWithPassword
  // also uses it to make loggingIn() be true during the beginPasswordExchange
  // method call too.
  Accounts._setLoggingIn = function (x) {
    if (loggingIn !== x) {
      loggingIn = x;
      loggingInDeps.changed();
    }
  };

  /**
   * @summary True if a login method (such as `Meteor.loginWithPassword`, `Meteor.loginWithFacebook`, or `Accounts.createUser`) is currently in progress. A reactive data source.
   * @locus Client
   */
  Meteor.loggingIn = function () {
    loggingInDeps.depend();
    return loggingIn;
  };

  ///
  /// LOGIN METHODS
  ///

  // Call a login method on the server.
  //
  // A login method is a method which on success calls `this.setUserId(id)` and
  // `Accounts._setLoginToken` on the server and returns an object with fields
  // 'id' (containing the user id), 'token' (containing a resume token), and
  // optionally `tokenExpires`.
  //
  // This function takes care of:
  //   - Updating the Meteor.loggingIn() reactive data source
  //   - Calling the method in 'wait' mode
  //   - On success, saving the resume token to localStorage
  //   - On success, calling Accounts.connection.setUserId()
  //   - Setting up an onReconnect handler which logs in with
  //     the resume token
  //
  // Options:
  // - methodName: The method to call (default 'login')
  // - methodArguments: The arguments for the method
  // - validateResult: If provided, will be called with the result of the
  //                 method. If it throws, the client will not be logged in (and
  //                 its error will be passed to the callback).
  // - userCallback: Will be called with no arguments once the user is fully
  //                 logged in, or with the error on error.
  //
  Accounts.callLoginMethod = function (options) {
    options = _.extend({
      methodName: 'login',
      methodArguments: [{}],
      _suppressLoggingIn: false
    }, options);
    // Set defaults for callback arguments to no-op functions; make sure we
    // override falsey values too.
    _.each(['validateResult', 'userCallback'], function (f) {
      if (!options[f])
        options[f] = function () {};
    });
    // make sure we only call the user's callback once.
    var onceUserCallback = _.once(options.userCallback);

    var reconnected = false;

    // We want to set up onReconnect as soon as we get a result token back from
    // the server, without having to wait for subscriptions to rerun. This is
    // because if we disconnect and reconnect between getting the result and
    // getting the results of subscription rerun, we WILL NOT re-send this
    // method (because we never re-send methods whose results we've received)
    // but we WILL call loggedInAndDataReadyCallback at "reconnect quiesce"
    // time. This will lead to makeClientLoggedIn(result.id) even though we
    // haven't actually sent a login method!
    //
    // But by making sure that we send this "resume" login in that case (and
    // calling makeClientLoggedOut if it fails), we'll end up with an accurate
    // client-side userId. (It's important that livedata_connection guarantees
    // that the "reconnect quiesce"-time call to loggedInAndDataReadyCallback
    // will occur before the callback from the resume login call.)
    var onResultReceived = function (err, result) {
      if (err || !result || !result.token) {
        Accounts.connection.onReconnect = null;
      } else {
        Accounts.connection.onReconnect = function () {
          reconnected = true;
          // If our token was updated in storage, use the latest one.
          var storedToken = storedLoginToken();
          if (storedToken) {
            result = {
              token: storedToken,
              tokenExpires: storedLoginTokenExpires()
            };
          }
          if (! result.tokenExpires)
            result.tokenExpires = Accounts._tokenExpiration(new Date());
          if (Accounts._tokenExpiresSoon(result.tokenExpires)) {
            makeClientLoggedOut();
          } else {
            Accounts.callLoginMethod({
              methodArguments: [{resume: result.token}],
              // Reconnect quiescence ensures that the user doesn't see an
              // intermediate state before the login method finishes. So we don't
              // need to show a logging-in animation.
              _suppressLoggingIn: true,
              userCallback: function (error) {
                var storedTokenNow = storedLoginToken();
                if (error) {
                  // If we had a login error AND the current stored token is the
                  // one that we tried to log in with, then declare ourselves
                  // logged out. If there's a token in storage but it's not the
                  // token that we tried to log in with, we don't know anything
                  // about whether that token is valid or not, so do nothing. The
                  // periodic localStorage poll will decide if we are logged in or
                  // out with this token, if it hasn't already. Of course, even
                  // with this check, another tab could insert a new valid token
                  // immediately before we clear localStorage here, which would
                  // lead to both tabs being logged out, but by checking the token
                  // in storage right now we hope to make that unlikely to happen.
                  //
                  // If there is no token in storage right now, we don't have to
                  // do anything; whatever code removed the token from storage was
                  // responsible for calling `makeClientLoggedOut()`, or the
                  // periodic localStorage poll will call `makeClientLoggedOut`
                  // eventually if another tab wiped the token from storage.
                  if (storedTokenNow && storedTokenNow === result.token) {
                    makeClientLoggedOut();
                  }
                }
                // Possibly a weird callback to call, but better than nothing if
                // there is a reconnect between "login result received" and "data
                // ready".
                onceUserCallback(error);
              }});
          }
        };
      }
    };

    // This callback is called once the local cache of the current-user
    // subscription (and all subscriptions, in fact) are guaranteed to be up to
    // date.
    var loggedInAndDataReadyCallback = function (error, result) {
      // If the login method returns its result but the connection is lost
      // before the data is in the local cache, it'll set an onReconnect (see
      // above). The onReconnect will try to log in using the token, and *it*
      // will call userCallback via its own version of this
      // loggedInAndDataReadyCallback. So we don't have to do anything here.
      if (reconnected)
        return;

      // Note that we need to call this even if _suppressLoggingIn is true,
      // because it could be matching a _setLoggingIn(true) from a
      // half-completed pre-reconnect login method.
      Accounts._setLoggingIn(false);
      if (error || !result) {
        error = error || new Error(
          "No result from call to " + options.methodName);
        onceUserCallback(error);
        return;
      }
      try {
        options.validateResult(result);
      } catch (e) {
        onceUserCallback(e);
        return;
      }

      // Make the client logged in. (The user data should already be loaded!)
      makeClientLoggedIn(result.id, result.token, result.tokenExpires);
      onceUserCallback();
    };

    if (!options._suppressLoggingIn)
      Accounts._setLoggingIn(true);
    Accounts.connection.apply(
      options.methodName,
      options.methodArguments,
      {wait: true, onResultReceived: onResultReceived},
      loggedInAndDataReadyCallback);
  };

  makeClientLoggedOut = function() {
    unstoreLoginToken();
    Accounts.connection.setUserId(null);
    Accounts.connection.onReconnect = null;
  };

  makeClientLoggedIn = function(userId, token, tokenExpires) {
    storeLoginToken(userId, token, tokenExpires);
    Accounts.connection.setUserId(userId);
  };

  /**
   * @summary Log the user out.
   * @locus Client
   * @param {Function} [callback] Optional callback. Called with no arguments on success, or with a single `Error` argument on failure.
   */
  Meteor.logout = function (callback) {
    Accounts.connection.apply('logout', [], {wait: true}, function(error, result) {
      if (error) {
        callback && callback(error);
      } else {
        makeClientLoggedOut();
        callback && callback();
      }
    });
  };

  /**
   * @summary Log out other clients logged in as the current user, but does not log out the client that calls this function.
   * @locus Client
   * @param {Function} [callback] Optional callback. Called with no arguments on success, or with a single `Error` argument on failure.
   */
  Meteor.logoutOtherClients = function (callback) {
    // We need to make two method calls: one to replace our current token,
    // and another to remove all tokens except the current one. We want to
    // call these two methods one after the other, without any other
    // methods running between them. For example, we don't want `logout`
    // to be called in between our two method calls (otherwise the second
    // method call would return an error). Another example: we don't want
    // logout to be called before the callback for `getNewToken`;
    // otherwise we would momentarily log the user out and then write a
    // new token to localStorage.
    //
    // To accomplish this, we make both calls as wait methods, and queue
    // them one after the other, without spinning off the event loop in
    // between. Even though we queue `removeOtherTokens` before
    // `getNewToken`, we won't actually send the `removeOtherTokens` call
    // until the `getNewToken` callback has finished running, because they
    // are both wait methods.
    Accounts.connection.apply(
      'getNewToken',
      [],
      { wait: true },
      function (err, result) {
        if (! err) {
          storeLoginToken(Meteor.userId(), result.token, result.tokenExpires);
        }
      }
    );
    Accounts.connection.apply(
      'removeOtherTokens',
      [],
      { wait: true },
      function (err) {
        callback && callback(err);
      }
    );
  };


////////////////////////////////////////////////////////////////
//
//
//
// Add basic functionality from the accounts-password client
//
//
//
////////////////////////////////////////////////////////////////

  // Attempt to log in with a password.
  //
  // @param selector {String|Object} One of the following:
  //   - {username: (username)}
  //   - {email: (email)}
  //   - a string which may be a username or email, depending on whether
  //     it contains "@".
  // @param password {String}
  // @param callback {Function(error|undefined)}

  /**
   * @summary Log the user in with a password.
   * @locus Client
   * @param {Object | String} user Either a string interpreted as a username or an email; or an object with a single key: `email`, `username` or `id`.
   * @param {String} password The user's password.
   * @param {Function} [callback] Optional callback. Called with no arguments on success, or with a single `Error` argument on failure.
   */
  Meteor.loginWithPassword = function (selector, password, callback) {
    if (typeof selector === 'string')
      if (selector.indexOf('@') === -1)
        selector = {username: selector};
      else
        selector = {email: selector};

    Accounts.callLoginMethod({
      methodArguments: [{
        user: selector,
        password: Accounts._hashPassword(password)
      }],
      userCallback: function (error, result) {
        if (error && error.error === 400 &&
            error.reason === 'old password format') {
          // The "reason" string should match the error thrown in the
          // password login handler in password_server.js.

          // XXX COMPAT WITH 0.8.1.3
          // If this user's last login was with a previous version of
          // Meteor that used SRP, then the server throws this error to
          // indicate that we should try again. The error includes the
          // user's SRP identity. We provide a value derived from the
          // identity and the password to prove to the server that we know
          // the password without requiring a full SRP flow, as well as
          // SHA256(password), which the server bcrypts and stores in
          // place of the old SRP information for this user.
          srpUpgradePath({
            upgradeError: error,
            userSelector: selector,
            plaintextPassword: password
          }, callback);
        }
        else if (error) {
          callback && callback(error);
        } else {
          callback && callback();
        }
      }
    });
  };

  Accounts._hashPassword = function (password) {
    return {
      digest: SHA256(password),
      algorithm: "sha-256"
    };
  };

  // XXX COMPAT WITH 0.8.1.3
  // The server requested an upgrade from the old SRP password format,
  // so supply the needed SRP identity to login. Options:
  //   - upgradeError: the error object that the server returned to tell
  //     us to upgrade from SRP to bcrypt.
  //   - userSelector: selector to retrieve the user object
  //   - plaintextPassword: the password as a string
  var srpUpgradePath = function (options, callback) {
    var details;
    try {
      details = EJSON.parse(options.upgradeError.details);
    } catch (e) {}
    if (!(details && details.format === 'srp')) {
      callback && callback(
        new Meteor.Error(400, "Password is old. Please reset your " +
                         "password."));
    } else {
      Accounts.callLoginMethod({
        methodArguments: [{
          user: options.userSelector,
          srp: SHA256(details.identity + ":" + options.plaintextPassword),
          password: Accounts._hashPassword(options.plaintextPassword)
        }],
        userCallback: callback
      });
    }
  };


  // Attempt to log in as a new user.

  /**
   * @summary Create a new user.
   * @locus Anywhere
   * @param {Object} options
   * @param {String} options.username A unique name for this user.
   * @param {String} options.email The user's email address.
   * @param {String} options.password The user's password. This is __not__ sent in plain text over the wire.
   * @param {Object} options.profile The user's profile, typically including the `name` field.
   * @param {Function} [callback] Client only, optional callback. Called with no arguments on success, or with a single `Error` argument on failure.
   */
  Accounts.createUser = function (options, callback) {
    options = _.clone(options); // we'll be modifying options

    if (typeof options.password !== 'string')
      throw new Error("Must set options.password");
    if (!options.password) {
      callback(new Meteor.Error(400, "Password may not be empty"));
      return;
    }

    // Replace password with the hashed password.
    options.password = Accounts._hashPassword(options.password);

    Accounts.callLoginMethod({
      methodName: 'createUser',
      methodArguments: [options],
      userCallback: callback
    });
  };



  // Change password. Must be logged in.
  //
  // @param oldPassword {String|null} By default servers no longer allow
  //   changing password without the old password, but they could so we
  //   support passing no password to the server and letting it decide.
  // @param newPassword {String}
  // @param callback {Function(error|undefined)}

  /**
   * @summary Change the current user's password. Must be logged in.
   * @locus Client
   * @param {String} oldPassword The user's current password. This is __not__ sent in plain text over the wire.
   * @param {String} newPassword A new password for the user. This is __not__ sent in plain text over the wire.
   * @param {Function} [callback] Optional callback. Called with no arguments on success, or with a single `Error` argument on failure.
   */
  Accounts.changePassword = function (oldPassword, newPassword, callback) {
    if (!Meteor.user()) {
      callback && callback(new Error("Must be logged in to change password."));
      return;
    }

    check(newPassword, String);
    if (!newPassword) {
      callback(new Meteor.Error(400, "Password may not be empty"));
      return;
    }

    Accounts.connection.apply(
      'changePassword',
      [oldPassword ? Accounts._hashPassword(oldPassword) : null,
       Accounts._hashPassword(newPassword)],
      function (error, result) {
        if (error || !result) {
          if (error && error.error === 400 &&
              error.reason === 'old password format') {
            // XXX COMPAT WITH 0.8.1.3
            // The server is telling us to upgrade from SRP to bcrypt, as
            // in Meteor.loginWithPassword.
            srpUpgradePath({
              upgradeError: error,
              userSelector: { id: Meteor.userId() },
              plaintextPassword: oldPassword
            }, function (err) {
              if (err) {
                callback && callback(err);
              } else {
                // Now that we've successfully migrated from srp to
                // bcrypt, try changing the password again.
                Accounts.changePassword(oldPassword, newPassword, callback);
              }
            });
          } else {
            // A normal error, not an error telling us to upgrade to bcrypt
            callback && callback(
              error || new Error("No result from changePassword."));
          }
        } else {
          callback && callback();
        }
      }
    );
  };

  // Sends an email to a user with a link that can be used to reset
  // their password
  //
  // @param options {Object}
  //   - email: (email)
  // @param callback (optional) {Function(error|undefined)}

  /**
   * @summary Request a forgot password email.
   * @locus Client
   * @param {Object} options
   * @param {String} options.email The email address to send a password reset link.
   * @param {Function} [callback] Optional callback. Called with no arguments on success, or with a single `Error` argument on failure.
   */
  Accounts.forgotPassword = function(options, callback) {
    if (!options.email)
      throw new Error("Must pass options.email");
    Accounts.connection.call("forgotPassword", options, callback);
  };

  // Resets a password based on a token originally created by
  // Accounts.forgotPassword, and then logs in the matching user.
  //
  // @param token {String}
  // @param newPassword {String}
  // @param callback (optional) {Function(error|undefined)}

  /**
   * @summary Reset the password for a user using a token received in email. Logs the user in afterwards.
   * @locus Client
   * @param {String} token The token retrieved from the reset password URL.
   * @param {String} newPassword A new password for the user. This is __not__ sent in plain text over the wire.
   * @param {Function} [callback] Optional callback. Called with no arguments on success, or with a single `Error` argument on failure.
   */
  Accounts.resetPassword = function(token, newPassword, callback) {
    check(token, String);
    check(newPassword, String);

    if (!newPassword) {
      callback(new Meteor.Error(400, "Password may not be empty"));
      return;
    }

    Accounts.callLoginMethod({
      methodName: 'resetPassword',
      methodArguments: [token, Accounts._hashPassword(newPassword)],
      userCallback: callback});
  };

  // Verifies a user's email address based on a token originally
  // created by Accounts.sendVerificationEmail
  //
  // @param token {String}
  // @param callback (optional) {Function(error|undefined)}

  /**
   * @summary Marks the user's email address as verified. Logs the user in afterwards.
   * @locus Client
   * @param {String} token The token retrieved from the verification URL.
   * @param {Function} [callback] Optional callback. Called with no arguments on success, or with a single `Error` argument on failure.
   */
  Accounts.verifyEmail = function(token, callback) {
    if (!token)
      throw new Error("Need to pass token");

    Accounts.callLoginMethod({
      methodName: 'verifyEmail',
      methodArguments: [token],
      userCallback: callback});
  };


////////////////////////////////////////////////////////////////
//
// finally, we return our wrapped connection
//
////////////////////////////////////////////////////////////////
  connection.logout = Meteor.logout;
  connection.logoutOtherClients = Meteor.logoutOtherClients;
  connection.loginWithPassword = Meteor.loginWithPassword;
  connection.loginWithToken = Meteor.loginWithToken;
  return connection
};


