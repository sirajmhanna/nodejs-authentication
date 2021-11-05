module.exports = {
    apps: [
        {
            name: `${process.env.ENVIRONMENT}-nodejs-authentication`,
            script: "./server.js",
            watch: false,
            env: {
                ENVIRONMENT: `${process.env.ENVIRONMENT}`,
                PORT: `${process.env.PORT}`,
                SERVICE_NAME: `${process.env.SERVICE_NAME}`,
                MYSQL_DB_HOST: `${process.env.MYSQL_DB_HOST}`,
                MYSQL_DB_USER: `${process.env.MYSQL_DB_USER}`,
                MYSQL_DB_PASS: `${process.env.MYSQL_DB_PASS}`,
                MYSQL_DB_NAME: `${process.env.MYSQL_DB_NAME}`,
                MYSQL_DB_PORT: `${process.env.MYSQL_DB_PORT}`,
                NUMBER_OF_ALLOWED_FAILED_ATTEMPTS: `${process.env.NUMBER_OF_ALLOWED_FAILED_ATTEMPTS}`,
                ACCESS_TOKEN_CRYPTO_ID: `${process.env.ACCESS_TOKEN_CRYPTO_ID}`,
                ACCESS_TOKEN_CRYPTO_DATA: `${process.env.ACCESS_TOKEN_CRYPTO_DATA}`,
                ACCESS_TOKEN_KEY: `${process.env.ACCESS_TOKEN_KEY}`,
                ACCESS_TOKEN_TIME: `${process.env.ACCESS_TOKEN_TIME}`,
                REFRESH_TOKEN_CRYPTO_ID: `${process.env.REFRESH_TOKEN_CRYPTO_ID}`,
                REFRESH_TOKEN_CRYPTO: `${process.env.REFRESH_TOKEN_CRYPTO}`,
                REFRESH_TOKEN_KEY: `${process.env.REFRESH_TOKEN_KEY}`,
                REFRESH_TOKEN_TIME: `${process.env.REFRESH_TOKEN_TIME}`,
                PASSWORD_BCRYPT_ROUNDS: `${process.env.PASSWORD_BCRYPT_ROUNDS}`,
                RESET_PASSWORD_PIN_AGE: `${process.env.RESET_PASSWORD_PIN_AGE}`
            }
        }
    ]
};
