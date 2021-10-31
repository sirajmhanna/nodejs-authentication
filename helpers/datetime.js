/**
 * This function returns the date (YYYY-MM-DD)
 * @function millisecondsToYMD()
 * @param { Number } milliseconds 
 * @returns { Date }
 */
 exports.millisecondsToYMD = (milliseconds) => {
    try {
        const date = new Date(milliseconds);
        const year = date.getFullYear();
        const month = ("0" + (date.getMonth() + 1)).slice(-2);
        const day = ("0" + date.getDate()).slice(-2);

        return (`${year}-${month}-${day}`);
    } catch (error) {
        throw new Error(error);
    }
};

/**
 * This function changes JWT expire datetime into MySQL datetime
 * @function tokenExpiryDatetimeToMySQLDatetime()
 * @param { Date } expiryDate 
 * @returns { Date }
 */
 exports.tokenExpiryDatetimeToMySQLDatetime = (expiryDate) => {
    try {
        const date = new Date(expiryDate * 1000);
        return (date.toISOString().split('T')[0] + ' ' + date.toTimeString().split(' ')[0]);
    } catch (error) {
        throw new Error(error);
    }
};
