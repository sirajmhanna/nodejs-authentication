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
    },
    successLogout: {
        status: 'success',
        code: 200,
        message: 'successLogout'
    },
    newPasswordInvalid: {
        status: 'warn',
        code: 403,
        message: 'newPasswordInvalid'
    },
    currentPasswordInvalid: {
        status: 'warn',
        code: 403,
        message: 'currentPasswordMismatch'
    },
    successPasswordChange: {
        status: 'success',
        code: 200,
        message: 'passwordChangedSuccessfully'
    }
};
