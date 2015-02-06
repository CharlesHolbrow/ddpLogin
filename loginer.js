if (Meteor.isClient) {
 window.c = DDPLogin.wrapConnection(DDP.connect(Meteor.absoluteUrl()));
 window.l = function(e, r){
  console.log(e, r);
 };
}

if (Meteor.isServer) {
  Meteor.methods({
    user: function(){
      return Meteor.users.findOne(this.userId);
    },
    userId: function(){
      return this.userId;
    }
  });

  Meteor.startup(function () {
    console.log('---------Users--------');
    Meteor.users.find().forEach(function(u){
      console.log(JSON.stringify(u, null, 2));
      console.log('--------!!!--------');
    });
  });
}
