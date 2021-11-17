const logger = require("../../helpers/winston");
const { v4: uuidv4 } = require("uuid");

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
    logger.info(
      requestID,
      "Pin",
      "createResetPasswordPin",
      "Generating random pin code",
      {}
    );
    const randomPin =
      requestID +
      uuidv4() +
      require("../../helpers/generate").randomPassword(16);

    logger.info(
      requestID,
      "Pin",
      "createResetPasswordPin",
      "Executing MySQL Query",
      {}
    );
    const data = await connection.query(
      `
        INSERT 
            INTO
                users_pins (user_id, pin, expires_at)
            VALUES
                (?, ?, NOW() + INTERVAL ${process.env.RESET_PASSWORD_PIN_AGE} MINUTE)`,
      [ID, randomPin]
    );

    return data.affectedRows === 1 ? randomPin : false;
  } catch (error) {
    logger.error(requestID, "Pin", "createResetPasswordPin", "Error", {
      error: error.toString(),
    });
    throw new Error(error);
  }
};

/**
 * This function checks if the reset password pin is valid and returns the user ID
 * @function isResetPasswordPinValid()
 * @param { String } pin
 * @param { Number } requestID
 * @returns { Boolean | Object }
 */
Pin.isResetPasswordPinValid = async (connection, pin, requestID) => {
  try {
    logger.info(
      requestID,
      "Pin",
      "isResetPasswordPinValid",
      "Executing MySQL Query",
      {}
    );
    const data = await connection.query(
      `
        SELECT 
            users_pins.id AS pinID,
            users.id AS ID,
            users.first_name AS firstName,
            users.last_name AS lastName,
            users.email,
            users.phone
        FROM 
            users_pins, users
        WHERE 
            users_pins.deleted_at IS NULL
        AND
            users_pins.user_id = users.id
        AND
            users_pins.expires_at > NOW()
        AND
            users_pins.pin = ?
        GROUP BY
            users_pins.id`,
      [pin]
    );

    return data.length === 0 ? false : JSON.parse(JSON.stringify(data[0]));
  } catch (error) {
    logger.error(requestID, "Pin", "isResetPasswordPinValid", "Error", {
      error: error.toString(),
    });
    throw new Error(error);
  }
};

/**
 * This function destroys reset password pin
 * @function destroyResetPasswordPin()
 * @param { String } pin
 * @param { Number } requestID
 * @returns { Boolean }
 */
Pin.destroyResetPasswordPin = async (connection, pin, requestID) => {
  try {
    logger.info(
      requestID,
      "Pin",
      "destroyResetPasswordPin",
      "Executing MySQL Query",
      {}
    );
    const data = await connection.query(
      `
        UPDATE 
            users_pins 
        SET
            deleted_at = NOW()
        WHERE 
            deleted_at IS NULL
        AND
            pin = ?`,
      [pin]
    );

    return data.affectedRows === 1;
  } catch (error) {
    logger.error(requestID, "Pin", "destroyResetPasswordPin", "Error", {
      error: error.toString(),
    });
    throw new Error(error);
  }
};

module.exports = Pin;
