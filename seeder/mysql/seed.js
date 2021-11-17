const MySQL = require("../../config/mysql");
const logger = require("../../helpers/winston");

const databaseMigration = async (requestID) => {
  logger.info(
    requestID,
    "seeder",
    "databaseMigration",
    "Creating MySQL Connection :: Calling connection()",
    {}
  );
  const connection = await MySQL.connection();

  try {
    logger.info(
      `${requestID} :: databaseMigration :: Disabling foreign key constraints :: Executing MySQL Query`
    );
    await connection.query(`SET foreign_key_checks = 0`);

    logger.info(
      `${requestID} :: databaseMigration :: Setting utf8 unicode collation to database :: Executing MySQL Query`
    );
    await connection.query(
      `SELECT default_character_set_name FROM information_schema.SCHEMATA S WHERE schema_name = "nodejs"`
    );

    logger.info(`${requestID} :: databaseMigration :: Creating MySQL tables`);

    logger.info(
      `${requestID} :: databaseMigration :: Creating user_roles table`
    );
    await require("./create-tables").createUserRolesTable(
      connection,
      requestID
    );

    logger.info(`${requestID} :: databaseMigration :: Creating users table`);
    await require("./create-tables").createUsersTable(connection, requestID);

    logger.info(
      `${requestID} :: databaseMigration :: Creating authorization_tokens table`
    );
    await require("./create-tables").createAuthorizationTokensTable(
      connection,
      requestID
    );

    logger.info(
      `${requestID} :: databaseMigration :: Creating users_pins table`
    );
    await require("./create-tables").createUsersPinsTable(
      connection,
      requestID
    );

    logger.info(
      `${requestID} :: databaseMigration :: Done creating MySQL tables`
    );

    logger.info(`${requestID} :: databaseMigration :: Seeding data`);

    logger.info(
      `${requestID} :: databaseMigration :: Seeding user roles into user_roles table`
    );
    await require("./seed-data").seedUserRoles(connection, requestID);

    logger.info(
      `${requestID} :: databaseMigration :: Seeding root user data into users table`
    );
    await require("./seed-data").seedRootUser(connection, requestID);

    logger.info(
      `${requestID} :: databaseMigration :: Enabling foreign key constraints :: Executing MySQL Query`
    );
    await connection.query("SET foreign_key_checks = 1");

    logger.info(`${requestID} :: databaseMigration :: Done seeding data`);
  } catch (error) {
    logger.error(
      `${requestID} :: databaseMigration :: Error details: ${error}`
    );
    throw new Error(error);
  } finally {
    logger.info(
      requestID,
      "seeder",
      "databaseMigration",
      "Closing MySQL Connection :: Calling close()",
      {}
    );
    await connection.close();
  }
};

const executeCode = (requestID) => {
  console.log("Database migration process is about to start.");
  process.stdin.on("data", async (data) => {
    if (data.toString().trim().toLocaleLowerCase() === "yes")
      await databaseMigration(requestID);
    else if (data.toString().trim().toLocaleLowerCase() === "no")
      process.stdin.end();
    else process.stdout.write("Do you want to proceed(yes/no)?");
  });
  process.stdout.write("Do you want to proceed(yes/no)?");
};

executeCode(new Date().getTime());
