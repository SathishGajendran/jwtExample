var express = require('express'),
  bodyParser = require('body-parser');


var app = express();

app.use(bodyParser.urlencoded({
  extended: true
}));

app.use(bodyParser.json());

app.use('/auth',require('./auth/auth.controller'))

app.get('/',function(req, res) {
  res.send('Hello');
});


app.listen(3000,function(d){console.log("server started")});