const logger = require("../../helpers/winston");
const commonResponses = require("../../helpers/common-responses");
const MySQL = require("../../config/mysql");
const Token = require("../models/Token");
const User = require("../models/User");
const crypto = require("crypto-js");
let connection;

/**
 * Access Token Validator Controller
 * @method POST
 * @example body
 * { "accessToken": "xxxxxxxxxx" }
 * @example response
 * {
 *   status: 'success',
 *   code: 200,
 *   data: {
 *       user: { ... },
 *       isAccessTokenValid: true
 *   }
 * }
 * @param { Object } req
 * @param { Object } res
 * @returns { Object }
 */
exports.validateAccessToken = async (req, res) => {
  try {
    logger.info(
      req.body.requestID,
      "tokens",
      "validateAccessToken",
      "Starting execution",
      { ipAddress: req.ip }
    );

    logger.info(
      req.body.requestID,
      "tokens",
      "validateAccessToken",
      "Creating MySQL Connection :: Calling connection()",
      {}
    );
    connection = await MySQL.connection();

    logger.info(
      req.body.requestID,
      "tokens",
      "validateAccessToken",
      "Validating access token :: Calling isAccessTokenValid()",
      {}
    );
    const accessToken = await Token.isAccessTokenValid(
      connection,
      req.body.accessToken,
      req.body.requestID
    );

    if (!accessToken) {
      logger.warn(
        req.body.requestID,
        "tokens",
        "validateAccessToken",
        "Access token has expired or does not exists",
        {}
      );
      return res.status(401).json({
        status: "fail",
        code: 401,
        data: {
          isAccessTokenValid: false,
        },
      });
    }

    logger.info(
      req.body.requestID,
      "tokens",
      "validateAccessToken",
      "Returning success response",
      { userID: accessToken.ID }
    );
    return res.status(200).json({
      status: "success",
      code: 200,
      data: {
        user: accessToken,
        isAccessTokenValid: true,
      },
    });
  } catch (error) {
    logger.error(
      req.body.requestID,
      "tokens",
      "validateAccessToken",
      "Server Error",
      { error: error.toString() }
    );
    return res.status(500).json(commonResponses.genericErrorResponse);
  } finally {
    if (connection) {
      logger.info(
        req.body.requestID,
        "tokens",
        "validateAccessToken",
        "Closing MySQL Connection :: Calling close()",
        {}
      );
      await connection.close();
    }
  }
};

/**
 * Generate Access Token Controller
 * @method POST
 * @example body
 * { "refreshToken": "xxxxxxxx" }
 * @example response
 * {
 *   "status": "success",
 *   "code": 201,
 *   "message": "successRefreshToken",
 *   "user": {
 *       "ID": 1,
 *       "firstName": "Node",
 *       "lastName": "JS",
 *       "email": "nodejs@mailinator.com",
 *       "phone": "00000000",
 *       "roleID": 1,
 *       "roleCodename": "admin",
 *       "roleReadableNameEN": "Admin",
 *       "roleReadableNameAR": "مشرف"
 *   },
 *   "token": {
 *       "access": "xxxxxxxx",
 *       "time": "600"
 *   }
 * }
 * @param { Object } req
 * @param { Object } res
 * @returns { Object }
 */
exports.generateAccessToken = async (req, res) => {
  try {
    logger.info(
      req.body.requestID,
      "tokens",
      "generateAccessToken",
      "Starting execution",
      { ipAddress: req.ip }
    );

    if (!req.body?.refreshToken) {
      logger.error(
        req.body.requestID,
        "tokens",
        "generateAccessToken",
        "Refresh token is undefined",
        {}
      );
      return res.status(400).json(commonResponses.somethingWentWrong);
    }

    logger.info(
      req.body.requestID,
      "tokens",
      "generateAccessToken",
      "Creating MySQL Connection :: Calling connection()",
      {}
    );
    connection = await MySQL.connection();

    logger.info(
      req.body.requestID,
      "tokens",
      "generateAccessToken",
      "Checking if the refresh token exists and active :: Calling isRefreshTokenValid()",
      {}
    );
    const refreshTokenData = await Token.isRefreshTokenValid(
      connection,
      req.body.refreshToken,
      req.body.requestID
    );

    if (!refreshTokenData) {
      logger.warn(
        req.body.requestID,
        "tokens",
        "generateAccessToken",
        "Refresh token has expired",
        {}
      );
      return res.status(401).json(commonResponses.refreshTokenExpired);
    }

    logger.info(
      req.body.requestID,
      "tokens",
      "generateAccessToken",
      "Decoding refresh token data",
      {}
    );
    const userID = await crypto.AES.decrypt(
      refreshTokenData.ID,
      process.env.REFRESH_TOKEN_CRYPTO_ID
    ).toString(crypto.enc.Utf8);

    if (userID.length === 0) {
      logger.error(
        req.body.requestID,
        "tokens",
        "generateAccessToken",
        "Failed to decrypt user ID",
        {}
      );
      return res.status(401).json(commonResponses.somethingWentWrong);
    }

    logger.info(
      req.body.requestID,
      "tokens",
      "generateAccessToken",
      "Fetching user data",
      { userID }
    );
    const user = await User.getUserByID(connection, userID, req.body.requestID);

    if (!user) {
      logger.error(
        req.body.requestID,
        "tokens",
        "generateAccessToken",
        "Failed to fetch user",
        { userID }
      );
      return res.status(400).json(commonResponses.somethingWentWrong);
    }

    logger.info(
      req.body.requestID,
      "tokens",
      "generateAccessToken",
      "Adding access token :: Calling addAccessToken()",
      { user }
    );
    const accessToken = await Token.generateAccessToken(
      connection,
      user,
      req.body.requestID
    );

    if (!accessToken) {
      logger.error(
        req.body.requestID,
        "tokens",
        "generateAccessToken",
        `Failed to add access token`,
        {}
      );
      return res.status(400).json(commonResponses.somethingWentWrong);
    }

    logger.info(
      req.body.requestID,
      "tokens",
      "generateAccessToken",
      "Returning success response",
      { userID: user.ID }
    );
    return res.status(201).json({
      ...commonResponses.successRefreshToken,
      user,
      token: {
        access: accessToken,
        time: process.env.ACCESS_TOKEN_TIME.split("s")[0],
      },
    });
  } catch (error) {
    logger.error(
      req.body.requestID,
      "tokens",
      "generateAccessToken",
      "Server Error",
      { error: error.toString() }
    );
    return res.status(500).json(commonResponses.genericServerError);
  } finally {
    if (connection) {
      logger.info(
        req.body.requestID,
        "tokens",
        "generateAccessToken",
        "Closing MySQL Connection :: Calling close()",
        {}
      );
      await connection.close();
    }
  }
};
