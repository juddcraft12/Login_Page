var RateLimit = require('express-rate-limit');
var mysqlpool = require('./mysql').pool;
var moment = require('moment');

module.exports = function(app, passport,parameters) {


    const limiter = new RateLimit({
      windowMs: parameters.windowMs,
      max: parameters.max,
      delayMs: 0,
      message: 'Too many requests, please try again later.',
      onLimitReached: function(req, res, options){
        console.log("Limit Reached called");
        const myLockTime =  moment(new Date()).format("YYYY-MM-DD HH:mm:ss");
        const ipaddress = req.ip;

          mysqlpool.getConnection(function(err, connection){
            connection.query("select * from ipslocked where ipaddress = ?",[ipaddress],function(err,rows){
              if (err)
              {
                connection.release();
                return done(err);
              }
              if (rows.length>0) {
                if(rows[0].lastLockedTime!==null)
                {

                  connection.release();
                  return;
                }
                connection.query("update ipslocked set lastLockedTime= ? where ipaddress = ?",[myLockTime, ipaddress],function(err,result){
                  if(err){
                    console.log("Error updating locked time:"+err);
                    connection.release();
                    return err;
                  }
                  else{
                    connection.release();
                    return;
                  }
                });
              }
              else {
                const insertQuery = "insert into ipslocked ( ipaddress, lastLockedTime) values (?,?)";
                connection.query(insertQuery,[ipaddress, myLockTime],function(err,result){
                  if (err)
                  {
                    console.log("Error inserting new locked user:"+err);
                    connection.release();
                    return err;
                  }
                  else{
                    connection.release();
                    return;
                  }

              });
            }

          });

        });
      }
    });
    app.get('/login', isNotLoggedIn, function(req, res) {

        var options = {};
        options.message = req.flash('loginMessage');

        res.render('ejs/login', options);
    });

    app.post('/login', limiter, passport.authenticate('local-login', {
        successRedirect: '/profile', 
        failureRedirect: '/login', 
        failureFlash: true
    }));


    app.get('/register', isNotLoggedIn, function(req, res) {
        var options = {};
        options.message = req.flash('registerMessage');

        res.render('ejs/register', options);
    });

    app.post('/register', passport.authenticate('local-signup', {
        successRedirect: '/profile',
        failureRedirect: '/register',
        failureFlash: true
    }));


    app.get('/logout', isLoggedIn, function(req, res) {

        req.logout();
        res.redirect('/login');
    });


    app.get("/profile", isLoggedIn,
        function(req, res) {
            var options = {};
            options.user = req.user;
            res.render('ejs/profile', options);
        });



    app.get("/*", function(req, res) {
        res.render('ejs/index');
    });

    function isLoggedIn(req, res, next) {

        if (req.isAuthenticated())
            return next();
        res.redirect('/');
    }

    function isNotLoggedIn(req, res, next) {

        if (!req.isAuthenticated())
            return next();
        res.redirect('/profile');
    }
}
