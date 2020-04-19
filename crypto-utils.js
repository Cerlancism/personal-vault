//@ts-check

const crypto = require('crypto-js')

/**
 * 
 * @param {number} length 
 * @returns {string}
 */
function generateRandomHex(length)
{
    const rngLength = length < 4 ? 4 : length
    return crypto.lib.WordArray.random(rngLength).toString(crypto.enc.Hex).substr(0, length)
}

/**
 * 
 * @param {string} input 
 */
function generateHash(input)
{
    return crypto.SHA1(input).toString(crypto.enc.Hex)
}

/**
 * 
 * @param {string} input 
 * @param {string} salt 
 */
function getSaltedHash(input, salt)
{
    return generateHash(input + salt)
}

/**
 * 
 * @param {string} data 
 * @param {string} passphrase 
 * @returns {string}
 */
function encrypt(data, passphrase)
{
    return crypto.AES.encrypt(data, passphrase).toString()
}

/**
 * 
 * @param {string} encrpted 
 * @param {string} passphrase 
 * @returns {string}
 */
function decrypt(encrpted, passphrase)
{
    return crypto.AES.decrypt(encrpted, passphrase).toString(crypto.enc.Utf8)
}

module.exports = {
    generateRandomHex,
    generateHash,
    getSaltedHash,
    encrypt,
    decrypt
}