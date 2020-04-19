//@ts-check

const crypto = require('crypto-js')
const express = require('express')
const fs = require('fs')

//const app = express()

/**
 * 
 * @param {string} data 
 * @param {string} passphrase 
 * @returns {string}
 */
function encryptAES(data, passphrase)
{
    return crypto.AES.encrypt(data, passphrase).toString()
}

/**
 * 
 * @param {string} encrpted 
 * @param {string} passphrase 
 * @param {{value?: string}} out 
 */
function decryptAES(encrpted, passphrase, out)
{
    if (!out || !(Object.keys(out).length === 0 && out.constructor === Object))
    {
        throw "out needs an initial value"
    }

    const output = crypto.AES.decrypt(encrpted, passphrase)
    out.value = output.toString(crypto.enc.Utf8)

    return out.value.length != 0
}

/**
 * 
 * @param {number} length 
 * @returns {string}
 */
function generateRandomHex(length)
{
    return crypto.lib.WordArray.random(length / 2).toString(crypto.enc.Hex)
}

