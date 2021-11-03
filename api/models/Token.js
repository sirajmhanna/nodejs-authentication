const logger = require('../../helpers/winston');
const jwt = require('jsonwebtoken');
const crypto = require("crypto-js");
const datetimeHelpers = require('../../helpers/datetime');

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
        logger.info(requestID, 'Token', 'generateAccessToken', 'Hashing user data :: Calling Promise.all()', { userData });
        const promiseCrypto = await Promise.all([
            ,
            crypto.AES.encrypt(JSON.stringify({ userData }), process.env.ACCESS_TOKEN_CRYPTO_DATA).toString()
        ]);

        promiseCryptoData = {
            ID: promiseCrypto[0],
            data: promiseCrypto[1]
        };

        logger.info(requestID, 'Token', 'generateAccessToken', 'Creating access token', {});
        const accessToken = await jwt.sign(
            {
                ID: promiseCryptoData.ID,
                data: promiseCryptoData.data
            },
            process.env.ACCESS_TOKEN_KEY,
            {
                expiresIn: process.env.ACCESS_TOKEN_TIME
            }
        );

        logger.info(requestID, 'Token', 'generateAccessToken', 'Calculating token expire date :: Calling tokenExpiryDatetimeToMySQLDatetime()', {});
        const tokenExpireDatetime = datetimeHelpers.tokenExpiryDatetimeToMySQLDatetime(
            await jwt.verify(accessToken, process.env.ACCESS_TOKEN_KEY).exp);

        logger.info(requestID, 'Token', 'generateAccessToken', 'Executing MySQL Query', {});
        const data = await connection.query(`
        INSERT 
            INTO 
                authorization_tokens (user_id, token_type, token, expires_at)
            VALUES
                (?, ?, ?, ?)
        `, [userData.ID, 'access', accessToken, tokenExpireDatetime]);

        return data.affectedRows === 1 ? accessToken : false;
    } catch (error) {
        logger.error(requestID, 'Token', 'generateAccessToken', 'Error', { error: error.toString() });
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
        logger.info(requestID, 'Token', 'generateRefreshToken', 'Hashing user ID', { userID: ID });
        const cryptoID = await crypto.AES.encrypt(ID.toString(), process.env.REFRESH_TOKEN_CRYPTO_ID).toString();

        logger.info(requestID, 'Token', 'generateRefreshToken', 'Creating refresh token', {});
        const refreshToken = await jwt.sign(
            {
                ID: cryptoID
            },
            process.env.REFRESH_TOKEN_KEY,
            {
                expiresIn: process.env.REFRESH_TOKEN_TIME
            }
        );

        logger.info(requestID, 'Token', 'generateRefreshToken', 'Hashing refresh token :: Calling Promise.all()', {});
        const promises = await Promise.all([
            datetimeHelpers.tokenExpiryDatetimeToMySQLDatetime(await jwt.verify(refreshToken, process.env.REFRESH_TOKEN_KEY).exp),
            crypto.AES.encrypt(refreshToken, process.env.REFRESH_TOKEN_CRYPTO).toString()
        ]);

        const promisesData = {
            tokenExpireDatetime: promises[0],
            refreshTokenHash: promises[1]
        };

        logger.info(requestID, 'Token', 'generateRefreshToken', 'Executing MySQL Query', {});
        const data = await connection.query(`
        INSERT 
            INTO
                authorization_tokens (user_id, token_type, token, expires_at)
            VALUES
                (?, ?, ?, ?)
        `, [ID, 'refresh', refreshToken, promisesData.tokenExpireDatetime]);

        return data.affectedRows === 1 ? promisesData.refreshTokenHash : false;
    } catch (error) {
        logger.error(requestID, 'Token', 'generateRefreshToken', 'Error', { error: error.toString() });
        throw new Error(error);
    }
};

module.exports = Token;
