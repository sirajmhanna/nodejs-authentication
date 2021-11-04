const logger = require('../../helpers/winston');
const commonResponses = require('../../helpers/common-responses');
const MySQL = require('../../config/mysql');
const User = require('../models/User');
const Token = require('../models/Token');
const bcrypt = require('bcrypt');
const Pin = require('../models/Pin');
let connection, transaction;

/**
 * Login Controller
 * @method POST
 * @example body
 * {
 *   "email": "nodejs@mailinator.com",
 *   "password": "12345678"
 * }
 * @example response
 * {
 *   "status": "success",
 *   "code": 201,
 *   "message": "successLogin",
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
 *   "accessToken": {
 *       "access": "xxxxxxxxxxxxxxxx",
 *       "time": "60"
 *   }
 * }
 * @param { Object } req 
 * @param { Object } res 
 * @returns { Object }
 */
exports.login = async (req, res) => {
    try {
        logger.info(req.body.requestID, 'authentication', 'login', 'Starting execution', { ipAddress: req.ip });

        if (!req.body?.email || !req.body?.password) {
            logger.warn(req.body.requestID, 'authentication',
                'login', `${!req.body?.email ? 'email is undefined' : 'password is undefined'}`, {});
            return res.status(400).json(commonResponses.somethingWentWrong);
        }

        logger.info(req.body.requestID, 'authentication', 'login', 'Creating MySQL Connection :: Calling connection()', {});
        connection = await MySQL.connection();

        logger.info(req.body.requestID, 'authentication', 'login', 'Fetching user data :: Calling getUserByEmail()', {});
        const user = await User.getUserByEmail(connection, req.body.email, req.body.requestID);

        if (!user) {
            logger.warn(req.body.requestID, 'authentication', 'login', 'User email is not found', { email: req.body.email });
            return res.status(403).json(commonResponses.invalidLoginCredentials);
        }

        if (user.isLocked === 'true' || user.isSuspended === 'true') {
            logger.warn(req.body.requestID, 'authentication',
                'login', `${user.isLocked ? 'account is locked' : 'account is suspended'}`, { email: req.body.email });
            return res.status(403).json(commonResponses.invalidLoginCredentials);
        }

        logger.info(req.body.requestID, 'authentication', 'login', 'Starting MySQL Transaction :: Calling beginTransaction()', {});
        transaction = await connection.beginTransaction();

        logger.info(req.body.requestID, 'authentication', 'login', 'Validating password', {});
        if (!bcrypt.compareSync(req.body.password, user.password)) {
            logger.info(req.body.requestID, 'authentication', 'login',
                'Wrong password :: Incrementing Failed login attempts :: Calling incrementPreviousLockCountAttempts()', {});
            const increment = await User.incrementPreviousLockCountAttempts(connection, user.ID, req.body.requestID);

            if (!increment) {
                logger.error(req.body.requestID, 'authentication', 'login',
                    'Failed to increment failed login attempts :: Rolling Back MySQL Transaction :: Calling rollback()', { userID: user.ID });
                await connection.rollback();

                return res.status(400).json(commonResponses.somethingWentWrong);
            }

            logger.info(req.body.requestID, 'authentication', 'login', 'Committing MySQL Transaction :: Calling commit()', {});
            await connection.commit();

            return res.status(403).json(commonResponses.invalidLoginCredentials);
        }

        if (user.previousLockCount !== 0) {
            logger.info(req.body.requestID, 'authentication', 'login', 'Resetting previous lock count :: Calling resetPreviousLockCount()', {});
            if (! await User.resetPreviousLockCount(connection, user.ID, req.body.requestID)) {
                logger.error(req.body.requestID, 'authentication', 'login',
                    'Failed to reset previous lock count :: Rolling Back MySQL Transaction :: Calling rollback()', {});
                await connection.rollback();

                return res.status(400).json(commonResponses.somethingWentWrong);
            }
        }

        delete user.password;
        delete user.isLocked;
        delete user.isSuspended;
        delete user.previousLockCount;

        logger.info(req.body.requestID, 'authentication',
            'login', 'Calling generateAccessToken() :: Calling generateRefreshToken() :: In Promise.all()', {});
        const promises = await Promise.all([
            Token.generateAccessToken(connection, user, req.body.requestID),
            Token.generateRefreshToken(connection, user.ID, req.body.requestID)
        ]);

        const promisesData = {
            accessToken: promises[0],
            refreshToken: promises[1]
        };

        if (!promisesData.accessToken || !promisesData.refreshToken) {
            logger.error(req.body.requestID, 'authentication', 'login',
                `Failed to create ${promiseData.accessToken ? 'refresh' : 'access'} token :: Rolling Back MySQL Transaction :: Calling rollback()`, {});
            await connection.rollback();

            return res.status(400).json(commonResponses.somethingWentWrong);
        }

        logger.info(req.body.requestID, 'authentication', 'login',
            'Committing MySQL Transaction :: Calling commit() :: Returning success response', { userID: user.ID });
        await connection.commit();

        return res.status(201).json({
            ...commonResponses.successLogin,
            user,
            accessToken: {
                access: promisesData.accessToken,
                time: process.env.ACCESS_TOKEN_TIME.split("s")[0]
            },
            refreshToken: {
                refresh: promisesData.refreshToken,
                time: process.env.REFRESH_TOKEN_TIME.split("s")[0]
            }
        });
    } catch (error) {
        logger.error(req.body.requestID, 'authentication', 'login', 'Server Error', { error: error.toString() });
        if (transaction) {
            logger.error(req.body.requestID, 'authentication', 'login', 'Rolling Back MySQL Transaction :: Calling rollback()', {});
            await connection.rollback();
        }

        return res.status(500).json(commonResponses.genericServerError);
    } finally {
        if (connection) {
            logger.info(req.body.requestID, 'authentication', 'login', 'Closing MySQL Connection :: Calling close()', {});
            await connection.close();
        }
    }
};

/**
 * Logout Controller
 * @method POST
 * @example response
 * {
 *   "status": "success",
 *   "code": 200,
 *   "message": "successLogout"
 * }
 * @param { Object } req 
 * @param { Object } res 
 * @returns { Object }
 */
exports.logout = async (req, res) => {
    try {
        logger.info(req.body.requestID, 'authentication', 'logout', 'Starting execution', { ipAddress: req.ip, userID: req.body.userData.ID });

        if (!req.body?.refreshToken || !req.headers?.authorization) {
            logger.warn(req.body.requestID, 'authentication',
                'logout', `${!req.body?.refreshToken ? 'refresh token is not defined' : 'access token is not defined'}`, {});
            return res.status(400).json(commonResponses.somethingWentWrong);
        }

        logger.info(req.body.requestID, 'authentication', 'logout', 'Creating MySQL Connection :: Calling connection()', {});
        connection = await MySQL.connection();

        logger.info(req.body.requestID, 'authentication', 'logout', 'Starting MySQL Transaction :: Calling beginTransaction()', {});
        transaction = await connection.beginTransaction();

        logger.info(req.body.requestID, 'authentication', 'logout',
            'Blacklisting access and refresh token :: Calling blacklistToken() :: Calling blacklistToken() :: In Promise.all()', {});
        const promises = await Promise.all([
            await Token.blacklistToken(connection, req.headers.authorization, req.body.requestID),
            await Token.blacklistToken(connection, req.body.refreshToken, req.body.requestID)
        ]);

        const promisesData = {
            blacklistAccessToken: promises[0],
            blacklistRefreshToken: promises[1]
        }

        if (!promisesData.blacklistAccessToken || !promisesData.blacklistRefreshToken) {
            logger.error(req.body.requestID, 'authentication', 'logout',
                `Failed to blacklist ${!promisesData.blacklistAccessToken ? 'access' : 'refresh'} token :: 
                Rolling Back MySQL Transaction :: Calling rollback()`, {});
            await connection.rollback();

            return res.status(400).json(commonResponses.somethingWentWrong);
        }

        logger.info(req.body.requestID, 'authentication',
            'logout', 'Committing MySQL Transaction :: Calling commit() :: Returning success response', {});
        await connection.commit();

        return res.status(200).json(commonResponses.successLogout);
    } catch (error) {
        logger.error(req.body.requestID, 'authentication', 'logout', 'Server Error', { error: error.toString() });
        if (transaction) {
            logger.error(req.body.requestID, 'authentication', 'logout', 'Rolling Back MySQL Transaction :: Calling rollback()', {});
            await connection.rollback();
        }

        return res.status(500).json(commonResponses.genericServerError);
    } finally {
        if (connection) {
            logger.info(req.body.requestID, 'authentication', 'logout', 'Closing MySQL Connection :: Calling close()', {});
            await connection.close();
        }
    }
};

/**
 * Change Password Controller
 * @method PATCH
 * @example body
 * {
 *   "currentPassword": "12345678",
 *   "newPassword": "Qwerty_1234"
 * }
 * @example response 
 * {
 *   "status": "success",
 *   "code": 200,
 *   "message": "passwordChangedSuccessfully"
 * }
 * @param { Object } req 
 * @param { Object } res 
 * @returns { Object }
 */
exports.changePassword = async (req, res) => {
    try {
        logger.info(req.body.requestID, 'authentication', 'changePassword', 'Starting execution', { ipAddress: req.ip, userID: req.body.userData.ID });

        logger.info(req.body.requestID, 'authentication', 'changePassword', 'Validating new password', {});
        if (! await require('../../helpers/password-validator').isPasswordValid(req.body.newPassword)) {
            logger.warn(req.body.requestID, 'authentication', 'changePassword', 'New password is invalid', {});
            return res.status(403).json(commonResponses.newPasswordInvalid);
        }

        logger.info(req.body.requestID, 'authentication', 'changePassword', 'Creating MySQL Connection :: Calling connection()', {});
        connection = await MySQL.connection();

        logger.info(req.body.requestID, 'authentication', 'changePassword', 'Starting MySQL Transaction :: Calling beginTransaction()', {});
        transaction = await connection.beginTransaction();

        logger.info(req.body.requestID, 'authentication', 'changePassword',
            'Calling isCurrentPasswordMatches() :: Calling changeUserPassword() :: In Promise.all()', { userID: req.body.userData.ID });
        const promises = await Promise.all([
            User.isCurrentPasswordMatches(connection, req.body.userData.ID, req.body.currentPassword, req.body.requestID),
            User.changeUserPassword(connection, req.body.userData.ID, req.body.newPassword, req.body.requestID)
        ]);

        const promisesData = {
            isCurrentPasswordMatches: promises[0],
            changeUserPassword: promises[1]
        };

        logger.info(req.body.requestID, 'authentication', 'changePassword', 'Checking if the current password matches', {});
        if (!promisesData.isCurrentPasswordMatches || !promisesData.changeUserPassword) {
            logger.error(req.body.requestID, 'authentication', 'changePassword',
                `${!promisesData.isCurrentPasswordMatches ? 'Current password does not match' : 'Failed to change user password'} ::
             Rolling Back MySQL Query :: Calling rollback()`, { userID: req.body.userData.ID });
            await connection.rollback();

            return res.status(400).json(commonResponses.currentPasswordInvalid);
        }

        logger.info(req.body.requestID, 'authentication', 'changePassword',
            'Committing MySQL Transaction :: Calling commit() :: Returning success response', { accountName: req.body.accountName });
        await connection.commit();

        return res.status(200).json(commonResponses.successPasswordChange);
    } catch (error) {
        logger.error(req.body.requestID, 'authentication', 'changePassword', 'Server Error', { error: error.toString() });
        if (transaction) {
            logger.error(req.body.requestID, 'authentication', 'changePassword', 'Rolling Back MySQL Transaction :: Calling rollback()', {});
            await connection.rollback();
        }

        return res.status(500).json(commonResponses.genericServerError);
    } finally {
        if (connection) {
            logger.info(req.body.requestID, 'authentication', 'changePassword', 'Closing MySQL Connection :: Calling close()', {});
            await connection.close();
        }
    }
};

/**
 * Request Reset Password Controller
 * @method GET
 * @example query parameters
 * email=nodejs@mailinator.com
 * @example response
 * {
 *   "status": "success",
 *   "code": 200,
 *   "message": "passwordResetSuccessfulRequest"
 * }
 * @param { Object } req 
 * @param { Object } res 
 * @returns { Object }
 */
exports.requestResetPassword = async (req, res) => {
    try {
        logger.info(req.query.requestID, 'authentication', 'requestResetPassword', 'Starting execution', { ipAddress: req.ip });

        logger.info(req.query.requestID, 'authentication', 'requestResetPassword', 'Creating MySQL Connection :: Calling connection()', {});
        connection = await MySQL.connection();

        logger.info(req.query.requestID, 'authentication',
            'requestResetPassword', 'Fetching user data :: Calling getUserByEmail()', { email: req.query.email });
        const user = await User.getUserByEmail(connection, req.query.email, req.query.requestID);

        if (!user) {
            logger.info(req.query.requestID, 'authentication',
                'requestResetPassword', 'Email does not exists or inactive', { email: req.query.email });
            return res.status(200).json(commonResponses.successRequestResetPassword);
        }

        if (user.isSuspended === 'true') {
            logger.info(req.query.requestID, 'authentication', 'requestResetPassword', 'User account suspended', { email: req.query.email });
            return res.status(200).json(commonResponses.successRequestResetPassword);
        }

        logger.info(req.query.requestID, 'authentication', 'requestResetPassword', 'Starting MySQL Transaction :: Calling beginTransaction()', {});
        transaction = await connection.beginTransaction();

        logger.info(req.query.requestID, 'authentication', 'requestResetPassword', 'Creating reset pin :: Calling createResetPasswordPin()', {});
        const resetPasswordPin = await Pin.createResetPasswordPin(connection, user.ID, req.query.requestID);

        if (!resetPasswordPin) {
            logger.error(req.query.requestID, 'authentication', 'requestResetPassword',
                'Failed to create reset password pin :: Rolling Back MySQL Transaction :: Calling rollback()', {});
            await connection.rollback();

            return res.status(400).json(commonResponses.somethingWentWrong);
        }

        // To-DO
        // Send email
        // const emailPayload = {
        //     email: userData.email,
        //     resetPasswordURL: `${req.query.frontendBaseURL}/password/confirm/${resetPasswordPin}`
        // };

        logger.info(req.query.requestID, 'authentication', 'requestResetPassword',
            'Committing MySQL Transaction :: Calling commit() :: Returning success response', { userID: user.ID });
        await connection.commit();

        return res.status(200).json(commonResponses.successRequestResetPassword);
    } catch (error) {
        logger.error(req.query.requestID, 'authentication', 'requestResetPassword', 'Server Error', { error: error.toString() });
        if (transaction) {
            logger.error(req.query.requestID, 'authentication', 'requestResetPassword', 'Rolling Back MySQL Transaction :: Calling rollback()', {});
            await connection.rollback();
        }

        return res.status(500).json(commonResponses.genericServerError);
    } finally {
        if (connection) {
            logger.info(req.query.requestID, 'authentication', 'requestResetPassword', 'Closing MySQL Connection :: Calling close()', {});
            await connection.close();
        }
    }
};

/**
 * Confirm Reset Password Controller
 * @method PATCH
 * @example body
 * {
 *   "password": "Qwerty_1234",
 *   "pin": "xxxxxxxxxx"
 * }
 * @example response
 * {
 *   "status": "success",
 *   "code": 200,
 *   "message": "passwordResetSuccessful"
 * }
 * @param { Object } req 
 * @param { Object } res 
 * @returns { Object }
 */
exports.confirmResetPassword = async (req, res) => {
    try {
        logger.info(req.body.requestID, 'authentication', 'confirmResetPassword', 'Starting execution', { ipAddress: req.ip });

        logger.info(req.body.requestID, 'authentication', 'confirmResetPassword', 'Checking if the new password is valid via password-validator package', {});
        if (! await require('../../helpers/password-validator').isPasswordValid(req.body.password)) {
            logger.info(req.body.requestID, 'authentication', 'confirmResetPassword', 'New password is invalid', {});
            return res.status(400).json(commonResponses.newPasswordInvalid);
        }

        logger.info(req.query.requestID, 'authentication', 'confirmResetPassword', 'Creating MySQL Connection :: Calling connection()', {});
        connection = await MySQL.connection();

        logger.info(req.body.requestID, 'authentication', 'confirmResetPassword',
            'Checking reset password pin if valid :: Calling isResetPasswordPinValid()', { pin: req.body.pin });
        const user = await Pin.isResetPasswordPinValid(connection, req.body.pin, req.body.requestID);

        if (!user) {
            logger.warn(req.body.requestID, 'authentication', 'confirmResetPassword',
                'Reset password pin is not valid or does not exists', { pin: req.body.pin });
            return res.status(403).json(commonResponses.invalidResetPinResponse);
        }

        logger.info(req.body.requestID, 'authentication', 'confirmResetPassword', 'Starting MySQL Transaction :: Calling beginTransaction()', {});
        transaction = await connection.beginTransaction();

        logger.info(req.body.requestID, 'authentication', 'confirmResetPassword',
            'Calling changeUserPassword() :: Calling destroyResetPasswordPin() :: Calling blacklistAllTokensByUserID() :: In Promise.all()',
            { userID: user.ID, pin: req.body.pin });
        const promises = await Promise.all([
            User.changeUserPassword(connection, user.ID, req.body.password, req.body.requestID),
            Pin.destroyResetPasswordPin(connection, req.body.pin, req.body.requestID),
            Token.blacklistAllTokensByUserID(connection, user.ID, req.body.requestID)
        ]);

        const promisesData = {
            changeUserPassword: promises[0],
            destroyResetPasswordPin: promises[1]
        };

        if (!promisesData.changeUserPassword || !promisesData.destroyResetPasswordPin) {
            logger.error(req.body.requestID, 'authentication', 'confirmResetPassword',
                `${!promisesData.changeUserPassword ? 'Failed to change user password' : 'Failed to destroy reset password pin'} 
            :: Rolling Back MySQL Query :: Calling rollback()`, { user, pin: req.body.pin });
            await connection.rollback();

            return res.status(400).json(commonResponses.somethingWentWrong);
        }

        // To-DO
        // Send notification email
        // Password reset email
        // const emailPayload = {
        //     email: user.email,
        //     ipAddress: req.ip,
        //     date: new Date()
        // };

        logger.info(req.body.requestID, 'authentication', 'confirmResetPassword',
            'Committing MySQL Transaction :: Calling commit() :: Returning success response', { userID: user.ID });
        await connection.commit();

        return res.status(200).json(commonResponses.successResetPassword);
    } catch (error) {
        logger.error(req.body.requestID, 'authentication', 'confirmResetPassword', 'Server Error', { error: error.toString() });
        if (transaction) {
            logger.error(req.body.requestID, 'authentication', 'confirmResetPassword', 'Rolling Back MySQL Transaction :: Calling rollback()', {});
            await connection.rollback();
        }

        return res.status(500).json(commonResponses.genericServerError);
    } finally {
        if (connection) {
            logger.info(req.body.requestID, 'authentication', 'confirmResetPassword', 'Closing MySQL Connection :: Calling close()', {});
            await connection.close();
        }
    }
};
