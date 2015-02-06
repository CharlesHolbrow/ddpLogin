if Meteor.isServer
  try
    Accounts.createUser
      username: 'charles'
      email: 'a@a.a'
      password: 'qwerty'
  catch error
    console.log 'Accounts.createUser error:', error

if Meteor.isClient

  baseConn = DDP.connect Meteor.absoluteUrl()
  wrapConn = DDPLogin.wrapConnection baseConn

  Tinytest.add 'ddp-login - our wrapConnection function returns the same thing', (test, cb)->
    test.equal baseConn, wrapConn
  
