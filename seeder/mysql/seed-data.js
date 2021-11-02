const logger = require('../../helpers/winston');

/**
 * This function seeds data into "user_roles" table
 * @function seedUserRolesTable()
 * @param { Object } connection
 * @param { Number } requestID 
 */
exports.seedUserRoles = async (connection, requestID) => {
    try {
        logger.info(requestID, 'seed-tables', 'seedUserRolesTable', 'Executing MySQL Query :: Adding user_roles', {});
        await connection.query(`
        INSERT 
            INTO 
                user_roles (code_name, readable_name_en, readable_name_ar)
            VALUES 
                ('admin', 'Admin', 'مشرف'),
                ('client', 'Client', 'زبون')
            `);

        logger.info(requestID, 'seed-tables', 'seedUserRolesTable', 'Done', {});
    } catch (error) {
        logger.error(requestID, 'seed-tables', 'seedUserRolesTable', 'Error', { error: error.toString() });
        throw new Error(error);
    }
};

/**
 * This function seeds root user data into "users" table
 * @function seedRootUser()
 * @param { Object } connection
 * @param { Number } requestID 
 */
exports.seedRootUser = async (connection, requestID) => {
    try {
        const userData = {
            firstName: 'Node',
            lastName: 'JS',
            email: 'nodejs@mailinator.com',
            phone: '00000000',
            password: await require('bcrypt').hash('12345678', 8),
            userRole: 'admin'
        };

        logger.info(requestID, 'seed-tables', 'seedRootUser', 'Executing MySQL Query :: Adding root user', {});
        await connection.query(`
        INSERT 
            INTO 
                users (first_name, last_name, email, phone, password, user_role_id)
            VALUES 
                (?, ?, ?, ?, ?, (SELECT id FROM user_roles WHERE deleted_at IS NULL AND code_name = ?))
            `, [userData.firstName, userData.lastName, userData.email, userData.phone, userData.password, userData.userRole]);

        logger.info(requestID, 'seed-tables', 'seedRootUser', 'Done', {});
    } catch (error) {
        logger.error(requestID, 'seed-tables', 'seedRootUser', 'Error', { error: error.toString() });
        throw new Error(error);
    }
};
