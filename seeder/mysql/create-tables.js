const logger = require('../../helpers/winston');

/**
 * This function creates table "user_roles" 
 * @function createUserRolesTable()
 * @param { Object } connection
 * @param { Number } requestID 
 */
exports.createUserRolesTable = async (connection, requestID) => {
    try {
        logger.info(requestID, 'create-tables', 'createUserRolesTable', 'Executing MySQL Query', {});
        await connection.query("CREATE TABLE IF NOT EXISTS user_roles (" +
            "id int UNSIGNED NOT NULL AUTO_INCREMENT," +
            "code_name varchar(255) NOT NULL," +
            "readable_name_en varchar(255) NOT NULL," +
            "readable_name_ar varchar(255) NOT NULL," +
            "created_at datetime NOT NULL DEFAULT CURRENT_TIMESTAMP," +
            "updated_at datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP," +
            "deleted_at datetime," +
            "PRIMARY KEY(`id`)" +
            ")");

        logger.info(requestID, 'create-tables', 'createUserRolesTable', `Done`, {});
    } catch (error) {
        logger.error(requestID, 'create-tables', 'createUserRolesTable', 'Error details', { error: error.toString() });
        throw new Error(error);
    }
};

/**
 * This function creates table "users" 
 * @function createUsersTable()
 * @param { Object } connection
 * @param { Number } requestID 
 */
exports.createUsersTable = async (connection, requestID) => {
    try {
        logger.info(requestID, 'create-tables', 'createUsersTable', `Creating table "users" :: Executing MySQL Query`, {});
        await connection.query("CREATE TABLE IF NOT EXISTS users (" +
            "id int UNSIGNED NOT NULL AUTO_INCREMENT," +
            "first_name varchar(255) NOT NULL," +
            "last_name varchar(255) NOT NULL," +
            "email varchar(255) NOT NULL," +
            "phone varchar(50) DEFAULT NULL," +
            "password varchar(255) NOT NULL," +
            "is_locked tinyint(1) NOT NULL DEFAULT 0," +
            "is_suspended tinyint(1) NOT NULL DEFAULT 0," +
            "pre_lock_count int NOT NULL DEFAULT 0," +
            "user_role_id int UNSIGNED NOT NULL," +
            "created_at datetime NOT NULL DEFAULT CURRENT_TIMESTAMP," +
            "updated_at datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP," +
            "deleted_at datetime," +
            "PRIMARY KEY(`id`)," +
            "FOREIGN KEY (`user_role_id`)" +
            "REFERENCES user_roles(`id`)" +
            ")");

        logger.info(requestID, 'create-tables', 'createUsersTable', `Done`, {});
    } catch (error) {
        logger.error(requestID, 'create-tables', 'createUsersTable', `Error`, { error: error.toString() });
        throw new Error(error);
    }
};

/**
 * This function creates table "authorization_tokens" 
 * @function createAuthorizationTokensTable()
 * @param { Object } connection
 * @param { Number } requestID 
 */
exports.createAuthorizationTokensTable = async (connection, requestID) => {
    try {
        logger.info(requestID, 'Seed', 'createAuthorizationTokensTable', 'Executing MySQL Query', {});
        await connection.query("CREATE TABLE IF NOT EXISTS authorization_tokens (" +
            "id int UNSIGNED NOT NULL AUTO_INCREMENT," +
            "user_id int UNSIGNED NOT NULL," +
            "token text DEFAULT NULL," +
            "expires_at datetime DEFAULT NULL," +
            "is_blacklisted tinyint(1) NOT NULL DEFAULT 0," +
            "created_at datetime NOT NULL DEFAULT current_timestamp()," +
            "updated_at datetime NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()," +
            "deleted_at datetime DEFAULT NULL," +
            "PRIMARY KEY(`id`)," +
            "FOREIGN KEY (`user_id`)" +
            "REFERENCES users(`id`)" +
            ")");

        logger.info(requestID, 'create-tables', 'createAuthorizationTokensTable', `Done`, {});
    } catch (error) {
        logger.error(requestID, 'Seed', 'createAuthorizationTokensTable', 'Error details', { error: error.toString() });
        throw new Error(error);
    }
};

/**
 * This function creates table "users_pins" 
 * @function createUsersPinsTable()
 * @param { Object } connection
 * @param { Number } requestID 
 */
exports.createUsersPinsTable = async (connection, requestID) => {
    try {
        logger.info(requestID, 'Seed', 'createUsersPinsTable', 'Executing MySQL Query', {});
        await connection.query("CREATE TABLE IF NOT EXISTS users_pins (" +
            "id int UNSIGNED NOT NULL AUTO_INCREMENT," +
            "user_id int UNSIGNED NOT NULL," +
            "pin varchar(100) NOT NULL," +
            "expires_at datetime DEFAULT NULL," +
            "created_at datetime NOT NULL DEFAULT current_timestamp()," +
            "updated_at datetime NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()," +
            "deleted_at datetime DEFAULT NULL," +
            "PRIMARY KEY(`id`)," +
            "FOREIGN KEY (`user_id`)" +
            "REFERENCES users(`id`)" +
            ")");

        logger.info(requestID, 'create-tables', 'createUsersPinsTable', `Done`, {});
    } catch (error) {
        logger.error(requestID, 'Seed', 'createUsersPinsTable', 'Error details', { error: error.toString() });
        throw new Error(error);
    }
};
