const logger = require('../../helpers/winston');
const commonResponses = require('../../helpers/common-responses');
const MySQL = require('../../config/mysql');
const Token = require('../models/Token');

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
        logger.info(req.body.requestID, 'tokens', 'validateAccessToken', 'Starting execution', { ipAddress: req.ip });

        logger.info(req.body.requestID, 'tokens', 'validateAccessToken', 'Creating MySQL Connection :: Calling connection()', {});
        connection = await MySQL.connection();

        logger.info(req.body.requestID, 'tokens',
            'validateAccessToken', 'Validating access token :: Calling isAccessTokenValid()', {});
        const accessToken = await Token.isAccessTokenValid(connection, req.body.accessToken, req.body.requestID);

        if (!accessToken) {
            logger.warn(req.body.requestID, 'tokens', 'validateAccessToken', 'Access token has expired or does not exists', {});
            return res.status(401).json({
                status: 'fail',
                code: 401,
                data: {
                    isAccessTokenValid: false
                }
            });
        }

        logger.info(req.body.requestID, 'tokens', 'validateAccessToken', 'Returning success response', { userID: accessToken.ID });
        return res.status(200).json({
            status: 'success',
            code: 200,
            data: {
                user: accessToken,
                isAccessTokenValid: true
            }
        });
    } catch (error) {
        logger.error(req.body.requestID, 'tokens', 'validateAccessToken', 'Server Error', { error: error.toString() });
        return res.status(500).json(commonResponses.genericErrorResponse);
    } finally {
        if (connection) {
            logger.info(req.body.requestID, 'tokens', 'validateAccessToken', 'Closing MySQL Connection :: Calling close()', {});
            await connection.close();
        }
    }
};
