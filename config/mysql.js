const util = require('util');
const mysql = require('mysql');

exports.connection = () => {
    const connection = mysql.createConnection({
        host: process.env.MYSQL_DB_HOST,
        user: process.env.MYSQL_DB_USER,
        password: process.env.MYSQL_DB_PASS,
        port: process.env.MYSQL_DB_PORT,
        database: process.env.MYSQL_DB_NAME,
        connectionLimit: 10,
        timezone: 'UTC'
    });

    return {
        query(sql, args) {
            return util.promisify(connection.query).call(connection, sql, args);
        },
        beginTransaction() {
            return util.promisify(connection.beginTransaction).call(connection);
        },
        commit() {
            return util.promisify(connection.commit).call(connection);
        },
        rollback() {
            return util.promisify(connection.rollback).call(connection);
        },
        close() {
            return util.promisify(connection.end).call(connection);
        }
    };
};
