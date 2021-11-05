const logger = require('../../helpers/winston');
const bcrypt = require('bcrypt');

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
            JSON_OBJECT(
                'roleID', user_roles.id,
                'codename', user_roles.code_name,
                'readableNameEN', user_roles.readable_name_en,
                'readableNameAR', user_roles.readable_name_ar
            ) AS role
		FROM
			users, user_roles
        WHERE
            users.deleted_at IS NULL
        AND
            user_roles.deleted_at IS NULL
        AND
            users.user_role_id = user_roles.id
        AND
            users.email = ?
        LIMIT 1`, [0, 0, email]);

        data.map(row => { data[0].role = JSON.parse(row.role) });
        return data.length === 0 ? false : data[0];
    } catch (error) {
        logger.error(requestID, 'User', 'getUserByEmail', 'Error', { error: error.toString() });
        throw new Error(error);
    }
};

/**
 * This function fetches user by ID
 * @function getUserByID()
 * @param { Object } connection 
 * @param { Number } ID 
 * @param { Number } requestID 
 * @returns { Boolean | Object }
 */
User.getUserByID = async (connection, ID, requestID) => {
    try {
        logger.info(requestID, 'User', 'getUserByID', 'Executing MySQL Query', { ID });
        const data = await connection.query(`
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
			users, user_roles
        WHERE
            users.deleted_at IS NULL
        AND
            user_roles.deleted_at IS NULL
        AND
            users.user_role_id = user_roles.id
        AND
            users.is_locked = ?
        AND
            users.is_suspended = ?
        AND
            users.id = ?
        LIMIT 1`, [0, 0, ID]);

        data.map(row => { data[0].role = JSON.parse(row.role) });
        return data.length === 0 ? false : data[0];
    } catch (error) {
        logger.error(requestID, 'User', 'getUserByID', 'Error', { error: error.toString() });
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

/**
 * This function checks if the given password matches the stored password
 * @function isCurrentPasswordMatches()
 * @param { Number } ID 
 * @param { String } password 
 * @param { Number } requestID 
 * @returns { Boolean }
 */
User.isCurrentPasswordMatches = async (connection, ID, password, requestID) => {
    try {
        logger.info(requestID, 'User', 'isCurrentPasswordMatches', 'Executing MySQL Query', { ID });
        const data = await connection.query(`
        SELECT 
            password
        FROM
            users
        WHERE 
            deleted_at IS NULL 
        AND 
            is_locked = 0 
        AND 
            id = ?`, [ID]);

        return (data.length === 0) ? false : await bcrypt.compare(password, JSON.parse(JSON.stringify(data[0])).password);
    } catch (error) {
        logger.error(requestID, 'User', 'isCurrentPasswordMatches', 'Error', { error: error.toString() });
        throw new Error(error);
    }
};

/**
 * This function changes user password 
 * Encrypts the new password
 * @function changeUserPassword()
 * @param { Number } ID 
 * @param { String } password 
 * @param { Number } requestID 
 * @returns { Boolean }
 */
User.changeUserPassword = async (connection, ID, password, requestID) => {
    try {
        logger.info(`${requestID} :: changePassword :: Hashing new password`);
        const hash = await bcrypt.hash(password, Number(process.env.PASSWORD_BCRYPT_ROUNDS));

        logger.info(requestID, 'User', 'changeUserPassword', 'Executing MySQL Query', { ID });
        const data = await connection.query(`
        UPDATE 
            users 
        SET
            password = ?
        WHERE 
            deleted_at IS NULL
        AND
            is_locked = ?
        AND
            id = ?`, [hash, 0, ID]);

        return data.affectedRows === 1;
    } catch (error) {
        logger.error(requestID, 'User', 'changeUserPassword', 'Error', { error: error.toString() });
        throw new Error(error);
    }
};

module.exports = User;
