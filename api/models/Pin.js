const logger = require('../../helpers/winston');
const { v4: uuidv4 } = require('uuid');

const Pin = {};

/**
 * This function generates and adds random reset password pin to 'users_pins' table 
 * @function createResetPasswordPin()
 * @param { Number } ID 
 * @param { Number } requestID 
 * @returns { String | Boolean }
 */
Pin.createResetPasswordPin = async (connection, ID, requestID) => {
    try {
        logger.info(requestID, 'Pin', 'createResetPasswordPin', 'Generating random pin code', {});
        const randomPin = requestID + '-' + uuidv4() + '-' + new Date().getSeconds();

        logger.info(requestID, 'Pin', 'createResetPasswordPin', 'Executing MySQL Query', {});
        const data = await connection.query(`
        INSERT 
            INTO
                users_pins (user_id, pin, expires_at)
            VALUES
                (?, ?, NOW() + INTERVAL ${process.env.RESET_PASSWORD_PIN_AGE} MINUTE)`,
            [ID, randomPin]);

        return data.affectedRows === 1 ? randomPin : false;
    } catch (error) {
        logger.error(requestID, 'Pin', 'createResetPasswordPin', 'Error', { error: error.toString() });
        throw new Error(error);
    }
};

module.exports = Pin;
