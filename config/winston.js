const winston = require("winston");

const loggerConfiguration = {
  transports: [
    new winston.transports.Console({
      level: "warn",
      filename: "logging/warn.log",
      format: winston.format.combine(winston.format.json()),
    }),
    new winston.transports.Console({
      level: "error",
      filename: "logging/error.log",
      format: winston.format.combine(winston.format.json()),
    }),
    new winston.transports.Console({
      level: "info",
      filename: "logging/all.log",
      format: winston.format.combine(winston.format.json()),
    }),
  ],
};

module.exports = { winston, loggerConfiguration };
