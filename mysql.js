var mysql = require('mysql');
const data = process.env['database']
const pass = process.env['password']
const username = process.env['user']
const hoster = process.env['host']
var pool =  mysql.createPool({
    connectionLimit : 100,
    host: hoster,
    port: 3306,
    user: username,
    password: pass,
    database: data,
    debug    :  false
});

exports.pool = pool;
