// =======================
// get the packages we need ============
// =======================
var express     = require('express');
var app         = express();
var bodyParser  = require('body-parser');
var morgan      = require('morgan');
var mongoose    = require('mongoose');

var bcrypt = require('bcrypt');
var SALT_WORK_FACTOR = 10;

var jwt    = require('jsonwebtoken'); // used to create, sign, and verify tokens
var config = require('./config'); // get our config file
var User   = require('./app/models/user'); // get our mongoose model
    
// =======================
// configuration =========
// =======================
var port = process.env.OPENSHIFT_NODEJS_PORT || 3500; // used to create, sign, and verify tokens
var ipAddress = process.env.OPENSHIFT_NODEJS_IP || "127.0.0.1";
// default to a 'localhost' configuration:
var connection_string = config.database;
// if OPENSHIFT env variables are present, use the available connection info:
if(process.env.OPENSHIFT_MONGODB_DB_PASSWORD){
  connection_string = process.env.OPENSHIFT_MONGODB_DB_USERNAME + ":" +
  process.env.OPENSHIFT_MONGODB_DB_PASSWORD + "@" +
  process.env.OPENSHIFT_MONGODB_DB_HOST + ':' +
  process.env.OPENSHIFT_MONGODB_DB_PORT + '/' +
  process.env.OPENSHIFT_APP_NAME;
}

mongoose.connect('mongodb://' + connection_string); // connect to database
app.set('superSecret', config.secret); // secret variable

// use body parser so we can get info from POST and/or URL parameters
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

// use morgan to log requests to the console
app.use(morgan('dev'));

app.use(function(req, res, next) {
  res.header("Access-Control-Allow-Origin", "*");
  res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept, authorization");
  next();
});

// =======================
// routes ================
// =======================
// basic route
app.get('/', function(req, res) {
    res.send('Hello! The API is at ip:' + port + '/api');
});

// API ROUTES -------------------

// get an instance of the router for api routes
var apiRoutes = express.Router(); 

// TODO: route to authenticate a user (POST http://localhost:8080/api/authenticate)
// route to authenticate a user (POST http://localhost:8080/api/authenticate)
apiRoutes.post('/authenticate', function(req, res) {

  // find the user
  User.findOne({
    name: req.body.name
  }, function(err, user) {

    if (err) throw err;

    if (!user) {
      res.json({ success: false, message: 'Authentication failed. User not found.' });
    } else if (user) {

      // check if password matches
      if (user.password != req.body.password) {
        res.json({ success: false, message: 'Authentication failed. Wrong password.' });
      } else {

        // if user is found and password is right
        // create a token
        var token = jwt.sign(user, app.get('superSecret'), {
          expiresIn : 1440 // expires in 1440 seconds
        });

        // return the information including token as JSON
        res.json({
          success: true,
          message: 'Enjoy your token!',
          token: token
        });
      }   

    }

  });
});
// TODO: route middleware to verify a token

// route to show a random message (GET http://localhost:8080/api/)
apiRoutes.get('/', function(req, res) {
  res.json({ message: 'Welcome to the coolest API on earth!' });
});

// route to return all users (GET http://localhost:8080/api/users)
apiRoutes.get('/users', function(req, res) {
  User.find({}, function(err, users) {
    res.json(users);
  });
});   

// apply the routes to our application with the prefix /api
app.use('/api', apiRoutes);

app.get('/setup', function(req, res) {

    var mySchema = User.schema;
     
    mySchema.pre('save', function(next){
        var user = this;
        if (!user.isModified('password')) return next();
     
        bcrypt.genSalt(SALT_WORK_FACTOR, function(err, salt){
            if(err) return next(err);
     
            bcrypt.hash(user.password, salt, function(err, hash){
                if(err) return next(err);
     
                user.password = hash;
                next();
            });
        });
    });
     
    /*var testdata = new  User({
        name: "admin",
       password: "test123"
    });
     
    testdata.save(function(err, data){
        if(err) console.log(err);
        else console.log ('Sucess:' , data);
    });*/
    
    // create a sample user
    var rainnier = new User({ 
    name: 'Rainnier', 
    password: 'rainnier',
    admin: true 
    });
    
    // save the sample user
    rainnier.save(function(err) {
        if (err) throw err;
        
        console.log('User saved successfully');
        res.json({ success: true });
    });

});


// =======================
// start the server ======
// =======================

var server = app.listen(port, ipAddress, function(){
  console.log('Magic happens at ' + ipAddress + ":" + port);
});