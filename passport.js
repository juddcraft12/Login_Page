var LocalStrategy   = require('passport-local').Strategy;
var bcrypt = require('bcrypt-nodejs');
var mysqlpool = require('./mysql').pool;
var moment = require('moment');




module.exports = function(passport, parameters) {


  const minutesLocked = parameters.minutesLocked;
      passport.serializeUser(function(user,done) {
  		done(null, user.id);
      });

      passport.deserializeUser(function(id,done) {
        mysqlpool.getConnection(function(err, connection){
          connection.query("select * from users where id = ?",[id],function(err,rows){
            if(err){
              connection.release();
              done(null,false);
            }
            else{
              connection.release();
        			done(err, rows[0]);
            }
          });

        });

    });


    passport.use('local-signup', new LocalStrategy({
      usernameField : 'username',
      passwordField : 'password',
      passReqToCallback : true
    },
    function(req, username, password, done) {
        process.nextTick(function(){
          const data = req.body;
          if(data.confirm!=data.password)
          {
            console.log("Passwords are not matching");
            return done(null, false, req.flash('registerMessage', 'Passwords are not matching.'));
          }

          mysqlpool.getConnection(function(err, connection){
            connection.query("select * from users where username = ?",[data.username],function(err,rows){

              if (err)
              {
                connection.release();
                return done(err);
              }

      			  if (rows.length>0) {
                console.log("That username is already taken");
                connection.release();
                return done(null, false, req.flash('registerMessage', 'That username is already taken.'));
              }
              else {


                const salt = bcrypt.genSaltSync(10);

                const newUserMysql = new Object();
                newUserMysql.username = data.username;
                newUserMysql.password = bcrypt.hashSync(data.password, salt);  
                newUserMysql.salt = salt;


                
        				const insertQuery = "insert into users ( username, password,salt) values (?,?,?)";
        				connection.query(insertQuery,[newUserMysql.username, newUserMysql.password, newUserMysql.salt],function(err,result){
                  if (err)
                  {
                    connection.release();
                    return done(err);
                  }

                  console.log(rows)
                  
                  newUserMysql.id = result.insertId;
                  
                  console.log(newUserMysql);
                  connection.release();
          				return done(null, newUserMysql);
                  
        			    });


              }

            });

          });

		    });
      }));

    function calculateMinutes(startDate,endDate)
    {
     
       var start_date = moment(startDate, 'YYYY-MM-DD HH:mm:ss');
       var end_date = moment(endDate, 'YYYY-MM-DD HH:mm:ss');
       var duration = moment.duration(end_date.diff(start_date));
       var minutes = duration.asMinutes();
       return minutes;
    }



    passport.use('local-login', new LocalStrategy({
          usernameField : 'username',
          passwordField : 'password',
          passReqToCallback : true
      },
      function(req, username, password, done) {
        process.nextTick(function(){
          const input = req.body;

          const data = {
              password : input.password,
              username : input.username
          };
          const ipaddress = req.ip;

          mysqlpool.getConnection(function(err, connection){

            connection.query("select * from ipslocked where ipaddress = ?",[ipaddress],function(iperr,ipdata){
              if (iperr)
              {
                connection.release();
                return done(iperr);
              }

              if(ipdata.length>0)
              {

                if(ipdata[0].lastLockedTime!=null)
                {
                  const lockedTime = moment(ipdata[0].lastLockedTime).format("YYYY-MM-DD HH:mm:ss");
                  const myCurrentTime =  moment(new Date()).format("YYYY-MM-DD HH:mm:ss");
                  console.log("LockedTIME:"+lockedTime);
                  console.log("myCurrentTime:"+myCurrentTime);
                  const lockMinutes = calculateMinutes(lockedTime,myCurrentTime);
                  console.log("Locked Minutes:"+lockMinutes);
                  if(lockMinutes>minutesLocked)
                  {

                    connection.query("update ipslocked set lastLockedTime = ? where ipaddress = ?",[null,ipaddress],function(newerr,result){
                      if (newerr)
                      {
                        console.log("Error resetting last locked date.")
                        connection.release();
                        return done(null, false, req.flash('loginMessage', 'Oops! Error resetting your last locked time.'));
                      }

                    });
                  }
                  else {

                    connection.release();
                    const minuteslabel = minutesLocked==1 ? " minute" : " minutes";
                    console.log("Your ipaddress is suspended for "+minutesLocked+ minuteslabel);
                    return done(null, false, req.flash('loginMessage', 'Your ipaddress is suspended for '+minutesLocked+ minuteslabel));
                  }
                }
              }


              connection.query("select * from users where username = ?",[data.username],function(err,rows){
                  if (err)
                  {
                    connection.release();
                    return done(err);
                  }

                  if (!rows.length) {

                    console.log("No user found");
                    connection.release();
                    return done(null, false, req.flash('loginMessage', 'No user found.'));
                  }
                  if (rows[0].failedLoginAttempts>1) {

                    console.log("Your account is locked");
                    connection.release();
                    return done(null, false, req.flash('loginMessage', 'Your account is locked.'));
                  }


                  const salt = rows[0].salt;
                  const hashpassword = bcrypt.hashSync(data.password,salt);
                  const storedpassword = rows[0].password;
                  console.log("New Password:"+hashpassword);
                  console.log("Stored Password:"+storedpassword)
                  if ( hashpassword !== storedpassword )
                  {

                    console.log("Password incorrect");
                    const newfailedcount = rows[0].failedLoginAttempts +1;
                    console.log("Failed attempts: "+rows[0].failedLoginAttempts)
                    connection.query("update users set failedLoginAttempts= ? where username = ?",[newfailedcount,rows[0].username],function(err,result){
                      if (err)
                      {
                        connection.release();
                        return done(null, false, req.flash('loginMessage', 'Oops! Error updating your failed count.')); 
                      }

                      connection.release();
                      return done(null, false, req.flash('loginMessage', 'Oops! Wrong password.'));
                    });

                  }
                  else {

                    const newfailedcount = 0;
                    connection.query("update users set failedLoginAttempts= ? where username = ?",[newfailedcount,rows[0].username],function(err,result){
                      if (err)
                      {
                        connection.release();
                        return done(null, false, req.flash('loginMessage', 'Oops! Error updating your failed count.'));
                      }

                      console.log(input.username+ " has logged in");

          						if (req.body.remember) {
                        console.log("Remember me");
          							req.session.cookie.maxAge =  60 * 1000;
          						} else {
                        console.log("Dont Remember");

          						}


                      connection.release();
                      return done(null, rows[0]);
                    });

                  }
              });
            });

    		  });

        });

      }));

};
