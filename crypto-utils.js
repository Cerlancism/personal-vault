//@ts-check

const crypto = require('crypto-js')

module.exports =
{
    /**
     * 
     * @param {number} length 
     * @returns {string}
     */
    generateRandomHex(length)
    {
        const rngLength = length < 4 ? 4 : length
        return crypto.lib.WordArray.random(rngLength).toString(crypto.enc.Hex).substr(0, length)
    },

    /**
     * 
     * @param {string} input 
     */
    generateHash(input)
    {
        return crypto.SHA1(input).toString(crypto.enc.Hex)
    },

    /**
     * 
     * @param {string} input 
     * @param {string} salt 
     */
    getSaltedHash(input, salt)
    {
        return module.exports.generateHash(input + salt)
    },

    /**
     * 
     * @param {string} data 
     * @param {string} passphrase 
     * @returns {string}
     */
    encrypt(data, passphrase)
    {
        return crypto.AES.encrypt(data, passphrase).toString()
    },

    /**
     * 
     * @param {string} encrpted 
     * @param {string} passphrase 
     * @returns {string}
     */
    decrypt(encrpted, passphrase)
    {
        return crypto.AES.decrypt(encrpted, passphrase).toString(crypto.enc.Utf8)
    },
}
