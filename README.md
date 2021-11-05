
# NodeJS Authentication Service

This is a repository built using NodeJS, ExpressJS, and MySQL.



## Features

User Authentication Service

## Tech Stack

**Server:** Node, Express, and MySQL


## Environment Variables

To run this project, you will need to add the following environment variables to your .env file

`PORT`
`SERVICE_NAME`
`ENVIRONMENT`

`MYSQL_DB_HOST`
`MYSQL_DB_USER`
`MYSQL_DB_PASSWORD`
`MYSQL_DB_NAME`
`MYSQL_DB_PORT`

`NUMBER_OF_ALLOWED_FAILED_ATTEMPTS`

`ACCESS_TOKEN_CRYPTO_ID`
`ACCESS_TOKEN_CRYPTO_DATA`
`ACCESS_TOKEN_KEY`
`ACCESS_TOKEN_TIME`

`REFRESH_TOKEN_CRYPTO_ID`
`REFRESH_TOKEN_CRYPTO`
`REFRESH_TOKEN_KEY`
`REFRESH_TOKEN_TIME`

`PASSWORD_BCRYPT_ROUNDS`

`RESET_PASSWORD_PIN_AGE`
## Run Locally

Clone the project

```bash
  git clone https://github.com/sirajmhanna/nodejs-authentication.git
```

Go to the project directory

```bash
  cd ./nodejs-authentication
```
Install dependencies

```bash
  npm ci
```

Create .env file (check .env.example file)

```bash
  touch .env 
```

Start the server

```bash
  npm run dev 
```

## Create Docs

```bash
node_modules/.bin/jsdoc -c ./jsdoc.conf.json
```