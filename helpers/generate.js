/**
 * This function generates random password
 * @param { Number } length
 * @returns { String }
 */
exports.randomPassword = (length) => {
  const characters =
    "2ijwI4XYghyN3oKfLE6dT7Oq5HU9nklz1ZxDVJCaS8bcpMmBRvPQFGtuWrse0A";

  let password = "";
  for (let count = 0; count < length; count++) {
    password += characters.charAt(Math.random() * characters.length);
  }

  return password;
};
