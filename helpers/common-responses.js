module.exports = {
    genericServerError: {
        status: 'fail',
        code: 500,
        message: 'serverError'
    },
    somethingWentWrong: {
        status: 'fail',
        code: 400,
        message: 'somethingWentWrong'
    },
    invalidLoginCredentials: {
        status: 'warn',
        code: 403,
        message: 'invalidLoginCredentials'
    },
    successLogin: {
        status: 'success',
        code: 201,
        message: 'successLogin'
    }
};
