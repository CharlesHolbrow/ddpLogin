Package.describe({
  name: 'ddp-login',
  version: '0.0.1',
  // Brief, one-line summary of the package.
  summary: 'Loggin to Meteor servers that have the accounts-password package',
  // URL to the Git repository containing the source code for this package.
  git: '',
  // By default, Meteor will default to using README.md for documentation.
  // To avoid submitting documentation, set this field to null.
  documentation: 'README.md'
});

Package.onUse(function(api) {
  api.versionsFrom('1.0.3.1');
  api.use(['coffeescript', 'tracker', 'underscore', 'sha'], 'client');
  api.export('DDPLogin', 'client');
  api.addFiles('ddp-login-client.js', 'client');
});

Package.onTest(function(api) {
  api.use(['tinytest', 'ddp', 'ddp-login', 'coffeescript', 'accounts-password']);
  api.addFiles('ddp-login-tests.coffee');
});
