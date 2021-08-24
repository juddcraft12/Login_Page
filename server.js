var path = require("path");
var express = require('express');
var cookieParser = require('cookie-parser');
var bodyParser = require('body-parser');
var morgan = require('morgan'); 
var app = express();
var port = process.env.PORT || 8080;
var server = require('http').createServer(app);
var session = require("express-session");
var passport = require("passport");
var flash = require('connect-flash');
const testmode = false;
const parameters = testmode ?
{
  minutesLocked: 1,
  windowMs: 10*1000,
  max: 2,

}
:
{
  minutesLocked: 20,
  windowMs: 10*60*1000,
  max: 12,
}

require('./passport')(passport,parameters);


app.use(cookieParser());
app.use(bodyParser.urlencoded({
    extended: true
}));
app.use(bodyParser.json());
app.use(session({
    secret: "thisisthesecretforsession",
    cookie: { maxAge: 10000 },
    resave: false,
    saveUninitialized: false
}));
app.use(passport.initialize());
app.use(passport.session()); 
app.use(flash());
const PATH_SRC = path.resolve(__dirname, 'views/public');
app.use(express.static(PATH_SRC));
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');

require('./routes')(app, passport,parameters);
server.listen(port, () => {
    var port1 = server.address().port;
    console.log('Server is listening at %s', ":" + port1);
});
