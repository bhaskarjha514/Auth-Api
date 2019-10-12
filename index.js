var mongodb = require('mongodb');
var ObjectID = mongodb.ObjectID;
var crypto = require('crypto')
var express = require('express');
var bodyParser = require('body-parser');

// PASSWORD UTILS
var getRandomString = function(length){
    return crypto.randomBytes(Math.ceil(length/2))
           .toString('hex') // convert t hexa format
           .slice(0,length);
}
var sha512 = function(password,salt){
    var hash = crypto.createHmac('sha512',salt);
    hash.update(password);
    var value = hash.digest('hex');
    return {
        salt:salt,
        passwordHash:value
    };
}
function saltHashPassword(userPassword){
    var salt = getRandomString(16);
    var passworData = sha512(userPassword,salt);
    return passworData;
}
function checkHashPassword(userPassword,salt){
    var passworData = sha512(userPassword,salt);
    return passworData;
}

var app = express();
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({extended: false}));

// Create MongoDB Client 
var MongoClient = mongodb.MongoClient;

// Connection URL 
var url = "mongodb://localhost:27017"
MongoClient.connect(url,{useNewUrlParser: true},function(err,client){
      if(err){
          console.log('Unable to connect to the mongoDB server.Error', err);
      }
      else{
        app.post('/signup',(request,response,next)=>{
              var post_data = request.body;

              var plaint_password = post_data.password;
              var hash_data = saltHashPassword(plaint_password);
              var password = hash_data.passwordHash; //save password hash 
              var salt = hash_data.salt;

              var username = post_data.username;
              var email = post_data.email;
              var insertJson = {
                  'email': email,
                  'password': password,
                  'salt': salt,
                  'username':username
              };
              var db = client.db('edmtdevnodejs');

              // check exists email
              db.collection('user')
                 .find({'email':email}).count(function(err,number){
                     if(number != 0){
                         response.json('Email already exists');
                         console.log('Email already exists');
                     }
                     else{
                         // insert data 
                         db.collection('user')
                           .insertOne(insertJson,function(error,res){
                            response.json('Signup Successfully');
                            console.log('Signup Successfully');
                           })
                     }
                 })
        });
        app.post('/login',(request,response,next)=>{
            var post_data = request.body;

            var email = post_data.email;
            var userPassword = post_data.password;
            
            var db = client.db('edmtdevnodejs');

            // check exists email
            db.collection('user')
               .find({'email':email}).count(function(err,number){
                   if(number == 0){
                       response.json('Email not exists');
                       console.log('Email not exists');
                   }
                   else{
                       // insert data 
                       db.collection('user')
                         .findOne({'email':email},function(err,user){
                            var salt = user.salt; //get salt from user
                            var hashed_password = checkHashPassword(userPassword,salt).passwordHash; // Hash password with salt
                            var encyrpted_password = user.password;
                            if(hashed_password == encyrpted_password){
                                response.json('Login success');
                                console.log('Login success');
                            }
                            else{
                                response.json('wrong password');
                                console.log('wrong password');

                            }
                         })
                   }
               })
      });
        app.listen(3000, ()=>{
              console.log('Connected to MongoDB Server,on port 3000');
          })
      }
});