/**
 * This function check if the password matches the requirements
 * @function isPasswordValid()
 * @example isPasswordValid()
 * password length between 8 and 100
 * has an uppercase
 * has digits
 * contains no space
 * @param { String } password
 * @returns { Boolean }
 */
exports.isPasswordValid = async (password) => {
  const passwordValidator = require("password-validator");
  const schema = new passwordValidator();

  schema
    .is()
    .min(8)
    .is()
    .max(100)
    .has()
    .uppercase()
    .has()
    .lowercase()
    .has()
    .digits(1)
    .has()
    .not()
    .spaces();

  return await schema.validate(password);
};
