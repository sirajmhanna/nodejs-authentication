const logger = require('../../helpers/winston');

const User = {};

/**
 * This function fetches user by email
 * @function getUserByEmail()
 * @param { Object } connection 
 * @param { String } email 
 * @param { Number } requestID 
 * @returns { Boolean | Object }
 */
User.getUserByEmail = async (connection, email, requestID) => {
    try {
        logger.info(requestID, 'User', 'getUserByEmail', 'Executing MySQL Query', { email });
        const data = await connection.query(`
        SELECT
            users.id AS ID,
            users.first_name AS firstName,
            users.last_name AS lastName,
            users.email,
            users.phone,
            users.password,
            IF(users.is_locked = ?, 'false', 'true') AS isLocked,
            IF(users.is_suspended = ?, 'false', 'true') AS isSuspended,
            users.pre_lock_count AS previousLockCount,
            user_roles.id AS roleID,
            user_roles.code_name AS roleCodename,
            user_roles.readable_name_en AS roleReadableNameEN,
            user_roles.readable_name_ar AS roleReadableNameAR
		FROM
			users, user_roles
        WHERE
            users.deleted_at IS NULL
        AND
            user_roles.deleted_at IS NULL
        AND
            users.user_role_id = user_roles.id
        AND
            users.email = ?`, [0, 0, email]);

        return data.length === 0 ? false : JSON.parse(JSON.stringify(data[0]));
    } catch (error) {
        logger.error(requestID, 'User', 'getUserByEmail', 'Error', { error: error.toString() });
        throw new Error(error);
    }
};

/**
 * This function increment previous failed login attempt and locks user account if the number of failed attempts exceeded predefined number
 * @function incrementPreviousLockCountAttempts()
 * @param { Object } connection 
 * @param { Number } ID 
 * @param { Number } requestID 
 * @returns { Boolean }
 */
User.incrementPreviousLockCountAttempts = async (connection, ID, requestID) => {
    try {
        logger.info(requestID, 'User', 'incrementPreviousLockCountAttempts', 'Executing MySQL Query', { userID: ID });
        const data = await connection.query(`
        UPDATE 
            users
        SET
            is_locked = CASE WHEN pre_lock_count = ? THEN 1 ELSE 0 END,
            pre_lock_count = CASE WHEN pre_lock_count < ? THEN pre_lock_count + 1 ELSE pre_lock_count END
        WHERE
            deleted_at IS NULL 
        AND 
            is_locked = ?
        AND
            is_suspended = ?
        AND 
            id = ?`,
            [
                process.env.NUMBER_OF_ALLOWED_FAILED_ATTEMPTS,
                process.env.NUMBER_OF_ALLOWED_FAILED_ATTEMPTS,
                0, 0, ID
            ]);

        return data.affectedRows === 1;
    } catch (error) {
        logger.error(requestID, 'User', 'incrementPreviousLockCountAttempts', 'Error', { error: error.toString() });
        throw new Error(error);
    }
};

/**
 * This function resets previous lock count 
 * @function resetPreviousLockCount()
 * @param { Object } connection 
 * @param { Number } ID 
 * @param { Number } requestID 
 * @returns { Boolean }
 */
User.resetPreviousLockCount = async (connection, ID, requestID) => {
    try {
        logger.info(requestID, 'User', 'resetPreviousLockCount', 'Executing MySQL Query', { userID: ID });
        const data = await connection.query(`
        UPDATE
            users
        SET
            pre_lock_count = ?
        WHERE
            deleted_at IS NULL
        AND
            is_locked = ?
        AND
            is_suspended = ?
        AND
            id = ?`, [0, 0, 0, ID]);

        return data.affectedRows === 1;
    } catch (error) {
        logger.error(requestID, 'User', 'resetPreviousLockCount', 'Error', { error: error.toString() });
        throw new Error(error);
    }
};

module.exports = User;
