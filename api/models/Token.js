const logger = require("../../helpers/winston");
const jwt = require("jsonwebtoken");
const crypto = require("crypto-js");
const datetimeHelpers = require("../../helpers/datetime");
const jwtHelpers = require("../../helpers/json-web-token");

const Token = {};

/**
 * This function generates access token
 * The generated token will be added into `authorization_tokens` table
 * @function generateAccessToken()
 * @param { Object } connection
 * @param { Object } userData
 * @param { Number } requestID
 * @returns { Boolean | String }
 */
Token.generateAccessToken = async (connection, userData, requestID) => {
  try {
    logger.info(
      requestID,
      "Token",
      "generateAccessToken",
      "Hashing user ID",
      { userData }
    );
    const userIDHash = await crypto.AES.encrypt(
      userData.ID.toString(),
      process.env.ACCESS_TOKEN_CRYPTO_ID
    ).toString();

    logger.info(
      requestID,
      "Token",
      "generateAccessToken",
      "Creating access token",
      {}
    );
    const accessToken = await jwt.sign(
      {
        ID: userIDHash,
      },
      process.env.ACCESS_TOKEN_KEY,
      {
        expiresIn: process.env.ACCESS_TOKEN_TIME,
      }
    );

    logger.info(
      requestID,
      "Token",
      "generateAccessToken",
      "Calculating token expire date :: Calling tokenExpiryDatetimeToMySQLDatetime()",
      {}
    );
    const tokenExpireDatetime =
      datetimeHelpers.tokenExpiryDatetimeToMySQLDatetime(
        await jwt.verify(accessToken, process.env.ACCESS_TOKEN_KEY).exp
      );

    logger.info(
      requestID,
      "Token",
      "generateAccessToken",
      "Executing MySQL Query",
      {}
    );
    const data = await connection.query(
      `
        INSERT 
            INTO 
                authorization_tokens (user_id, token_type, token, expires_at)
            VALUES
                (?, ?, ?, ?)
        `,
      [userData.ID, "access", accessToken, tokenExpireDatetime]
    );

    return data.affectedRows === 1 ? accessToken : false;
  } catch (error) {
    logger.error(requestID, "Token", "generateAccessToken", "Error", {
      error: error.toString(),
    });
    throw new Error(error);
  }
};

/**
 * This function generates refresh token
 * The generated token will be added into `authorization_tokens` table
 * @function generateAccessToken()
 * @param { Object } connection
 * @param { Number } ID
 * @param { Number } requestID
 * @returns { Boolean | String }
 */
Token.generateRefreshToken = async (connection, ID, requestID) => {
  try {
    logger.info(requestID, "Token", "generateRefreshToken", "Hashing user ID", {
      userID: ID,
    });
    const cryptoID = await crypto.AES.encrypt(
      ID.toString(),
      process.env.REFRESH_TOKEN_CRYPTO_ID
    ).toString();

    logger.info(
      requestID,
      "Token",
      "generateRefreshToken",
      "Creating refresh token",
      {}
    );
    const refreshToken = await jwt.sign(
      {
        ID: cryptoID,
      },
      process.env.REFRESH_TOKEN_KEY,
      {
        expiresIn: process.env.REFRESH_TOKEN_TIME,
      }
    );

    logger.info(
      requestID,
      "Token",
      "generateRefreshToken",
      "Hashing refresh token :: Calling Promise.all()",
      {}
    );
    const promises = await Promise.all([
      datetimeHelpers.tokenExpiryDatetimeToMySQLDatetime(
        await jwt.verify(refreshToken, process.env.REFRESH_TOKEN_KEY).exp
      ),
      crypto.AES.encrypt(
        refreshToken,
        process.env.REFRESH_TOKEN_CRYPTO
      ).toString(),
    ]);

    const promisesData = {
      tokenExpireDatetime: promises[0],
      refreshTokenHash: promises[1],
    };

    logger.info(
      requestID,
      "Token",
      "generateRefreshToken",
      "Executing MySQL Query",
      {}
    );
    const data = await connection.query(
      `
        INSERT 
            INTO
                authorization_tokens (user_id, token_type, token, expires_at)
            VALUES
                (?, ?, ?, ?)
        `,
      [
        ID,
        "refresh",
        promisesData.refreshTokenHash,
        promisesData.tokenExpireDatetime,
      ]
    );

    return data.affectedRows === 1 ? promisesData.refreshTokenHash : false;
  } catch (error) {
    logger.error(requestID, "Token", "generateRefreshToken", "Error", {
      error: error.toString(),
    });
    throw new Error(error);
  }
};

/**
 * This function blacklists token
 * @function blacklistToken()
 * @param { Object } connection
 * @param { String } token
 * @param { Number } requestID
 * @returns { Boolean }
 */
Token.blacklistToken = async (connection, token, requestID) => {
  try {
    logger.info(
      requestID,
      "Token",
      "blacklistToken",
      "Executing MySQL Query",
      {}
    );
    const data = await connection.query(
      `
        UPDATE
            authorization_tokens
        SET
            is_blacklisted = 1
        WHERE
            deleted_at IS NULL
        AND
            token = ?`,
      [token]
    );

    return data.affectedRows === 1;
  } catch (error) {
    logger.error(requestID, "Token", "blacklistToken", "Error", {
      error: error.toString(),
    });
    throw new Error(error);
  }
};

/**
 * This function validates access token and return user data if the token is valid
 * @function isAccessTokenValid()
 * @param { Object } connection
 * @param { String } token
 * @param { Number } requestID
 * @returns { Boolean | Object }
 */
Token.isAccessTokenValid = async (connection, token, requestID) => {
  try {
    logger.info(
      requestID,
      "Token",
      "isAccessTokenValid",
      "Verifying access token :: Calling verifyAccessToken()",
      {}
    );
    const tokenVerification = await jwtHelpers.verifyAccessToken(token);

    if (!tokenVerification) {
      logger.info(
        requestID,
        "Token",
        "isAccessTokenValid",
        "Access token has expired :: Blacklisting token :: Calling blacklistToken()",
        {}
      );
      if (!(await Token.blacklistToken(connection, token, requestID))) {
        logger.error(
          requestID,
          "Token",
          "isAccessTokenValid",
          "Failed to blacklist access token",
          {}
        );
      }

      return false;
    }

    logger.info(
      requestID,
      "Token",
      "isAccessTokenValid",
      "Decrypting token data",
      {}
    );
    const decrypt = await crypto.AES.decrypt(
      tokenVerification.ID,
      process.env.ACCESS_TOKEN_CRYPTO_ID
    );
    const userID = decrypt.toString(crypto.enc.Utf8);

    if (!userID || userID.length === 0) {
      logger.error(
        requestID,
        "Token",
        "isAccessTokenExistsAndActive",
        "Failed to decode access token data",
        {}
      );
      return false;
    }

    logger.info(
      requestID,
      "Token",
      "isAccessTokenValid",
      "Checking if token exists :: Executing MySQL Query",
      { userID }
    );
    const data = await connection.query(
      `
        SELECT
            users.id AS ID,
            users.first_name AS firstName,
            users.last_name AS lastName,
            users.email,
            users.phone,
            JSON_OBJECT(
                'roleID', user_roles.id,
                'codename', user_roles.code_name,
                'readableNameEN', user_roles.readable_name_en,
                'readableNameAR', user_roles.readable_name_ar
            ) AS role
		FROM
			users, user_roles, authorization_tokens
        WHERE
            users.deleted_at IS NULL
        AND
            user_roles.deleted_at IS NULL
        AND
            users.user_role_id = user_roles.id
        AND
            users.id = authorization_tokens.user_id
        AND
            users.is_locked = ? 
        AND
            users.is_suspended = ?
        AND
            users.id = ?
        AND
            authorization_tokens.token_type = ?
        AND
            authorization_tokens.is_blacklisted = ?
        AND
            authorization_tokens.token = ?`,
      [0, 0, userID, "access", 0, token]
    );

    data.map((row) => {
      row.role = JSON.parse(row.role);
    });
    return data.length === 0 ? false : data[0];
  } catch (error) {
    logger.error(requestID, "Token", "isAccessTokenValid", "Error", {
      error: error.toString(),
    });
    throw new Error(error);
  }
};

/**
 * This function validates refresh token and return decoded token if the token is valid
 * @function isRefreshTokenValid()
 * @param { Object } connection
 * @param { String } encodedRefreshToken
 * @param { Number } requestID
 * @returns { Boolean | String }
 */
Token.isRefreshTokenValid = async (
  connection,
  encodedRefreshToken,
  requestID
) => {
  try {
    logger.info(
      requestID,
      "Token",
      "isRefreshTokenValid",
      "Decrypting refresh token",
      {}
    );
    const bytes = await crypto.AES.decrypt(
      encodedRefreshToken.toString(),
      process.env.REFRESH_TOKEN_CRYPTO
    );
    const refreshToken = await bytes.toString(crypto.enc.Utf8);

    if (refreshToken.length === 0) {
      logger.warn(
        requestID,
        "Token",
        "isRefreshTokenValid",
        "Failed to decrypt refresh token",
        {}
      );
      return false;
    }

    logger.info(
      requestID,
      "Token",
      "isRefreshTokenValid",
      "Verifying refresh token :: Calling verifyRefreshToken()",
      {}
    );
    const tokenVerification = await jwtHelpers.verifyRefreshToken(refreshToken);

    if (!tokenVerification) {
      logger.info(
        requestID,
        "Token",
        "isRefreshTokenValid",
        "Refresh token has expired :: Blacklisting token :: Calling blacklistToken()",
        {}
      );
      if (
        !(await Token.blacklistToken(
          connection,
          encodedRefreshToken,
          requestID
        ))
      ) {
        logger.error(
          requestID,
          "Token",
          "isRefreshTokenValid",
          "Failed to blacklist refresh token",
          {}
        );
      }

      return false;
    }

    logger.info(
      requestID,
      "Token",
      "isRefreshTokenValid",
      "Checking if refresh token exists :: Executing MySQL Query",
      {}
    );
    const data = await connection.query(
      `
        SELECT 
            COUNT(id) AS count
        FROM 
            authorization_tokens
        WHERE
            deleted_at IS NULL
        AND
            token_type = ?
        AND
            is_blacklisted = ?
        AND
            token = ?`,
      ["refresh", 0, encodedRefreshToken]
    );

    return data[0].count === 0 ? false : tokenVerification;
  } catch (error) {
    logger.error(requestID, "Token", "isRefreshTokenValid", "Error", {
      error: error.toString(),
    });
    throw new Error(error);
  }
};

/**
 * This function blacklists all user tokens
 * @function blacklistAllTokensByUserID()
 * @param { Object } connection
 * @param { Number } userID
 * @param { Number } requestID
 */
Token.blacklistAllTokensByUserID = async (connection, userID, requestID) => {
  try {
    logger.info(
      requestID,
      "Token",
      "blacklistAllTokensByUserID",
      "Executing MySQL Query",
      { userID }
    );
    await connection.query(
      `
        UPDATE 
            authorization_tokens
        SET
            is_blacklisted = 1
        WHERE 
            deleted_at IS NULL
        AND
            user_id = ?`,
      [userID]
    );
  } catch (error) {
    logger.error(requestID, "Token", "blacklistAllTokensByUserID", "Error", {
      error: error.toString(),
    });
    throw new Error(error);
  }
};

module.exports = Token;
