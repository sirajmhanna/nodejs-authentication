const logger = require('../../helpers/winston');
const commonResponses = require('../../helpers/common-responses');
const MySQL = require('../../config/mysql');
const User = require('../models/User');
const Token = require('../models/Token');
const bcrypt = require('bcrypt');

exports.login = async (req, res) => {
    let connection, transaction;
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

        if (Number(user.previousLockCount) !== 0) {
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

            return res.status(400).json(commonResponses.somethingWentWrongResponse);
        }

        logger.info(req.body.requestID, 'authentication', 'login',
            'Committing MySQL Transaction :: Calling commit() :: Returning success response', {});
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
