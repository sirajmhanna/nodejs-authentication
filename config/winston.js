const winston = require('winston');
const datetime = require('../helpers/datetime');

const loggerConfiguration = {
    transports: [
        new winston.transports.Console({
            level: 'warn',
            filename: 'logging/warn.log',
            format: winston.format.combine(winston.format.json())
        }),
        new winston.transports.Console({
            level: 'error',
            filename: 'logging/error.log',
            format: winston.format.combine(winston.format.json())
        }),
        new winston.transports.Console({
            level: 'info',
            filename: 'logging/all.log',
            format: winston.format.combine(winston.format.json())
        })
    ]
};

/**
 * Winston Transport Level Info
 * @function info()
 * @param { Number } requestId 
 * @param { String } className 
 * @param { String } functionName 
 * @param { String } logMessage 
 * @param { Object } data 
 */
exports.info = (requestId, className, functionName, logMessage, data) => {
    winston.createLogger(loggerConfiguration).info(
        {
            requestID: requestId,
            date: datetime.millisecondsToYMD(new Date().getTime()),
            timestamp: new Date().getTime(),
            serviceName: process.env.SERVICE_NAME,
            className: className,
            functionName: functionName,
            logMessage: logMessage,
            data
        });
};

/**
 * Winston Transport Level Warn
 * @function info()
 * @param { Number } requestId 
 * @param { String } className 
 * @param { String } functionName 
 * @param { String } logMessage 
 * @param { Object } data 
 */
exports.warn = (requestId, className, functionName, logMessage, data) => {
    winston.createLogger(loggerConfiguration).warn({
        requestID: requestId,
        date: datetime.millisecondsToYMD(new Date().getTime()),
        timestamp: new Date().getTime(),
        serviceName: process.env.SERVICE_NAME,
        className: className,
        functionName: functionName,
        logMessage: logMessage,
        data
    });
};

/**
 * Winston Transport Level Error
 * @function info()
 * @param { Number } requestId 
 * @param { String } className 
 * @param { String } functionName 
 * @param { String } logMessage 
 * @param { Object } data 
 */
exports.error = (requestId, className, functionName, logMessage, data) => {
    winston.createLogger(loggerConfiguration).error({
        requestID: requestId,
        date: datetime.millisecondsToYMD(new Date().getTime()),
        timestamp: new Date().getTime(),
        serviceName: process.env.SERVICE_NAME,
        className: className,
        functionName: functionName,
        logMessage: logMessage,
        data
    });
};
