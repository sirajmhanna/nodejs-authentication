const jwt = require("jsonwebtoken");
const logger = require("../helpers/winston");

/**
 * This function verifies refresh token
 * @function verifyRefreshToken()
 * @param { String } token
 * @returns { Object } Decoded token will be returned after verification
 */
exports.verifyRefreshToken = async (token) => {
  try {
    return await jwt.verify(token, process.env.REFRESH_TOKEN_KEY);
  } catch (error) {
    if (error.name === "TokenExpiredError") {
      logger.warn(
        new Date().getTime(),
        "json-web-token",
        "verifyRefreshToken",
        "Token has expired",
        {}
      );
      return false;
    } else {
      throw new Error(error);
    }
  }
};

/**
 * This function verifies access token
 * @function verifyAccessToken()
 * @param { String } token
 * @returns { Object } Decoded token will be returned after verification
 */
exports.verifyAccessToken = async (token) => {
  try {
    return await jwt.verify(token, process.env.ACCESS_TOKEN_KEY);
  } catch (error) {
    if (error.name === "TokenExpiredError") {
      logger.warn(
        new Date().getTime(),
        "json-web-token",
        "verifyAccessToken",
        "Token has expired",
        {}
      );
      return false;
    } else {
      throw new Error(error);
    }
  }
};
