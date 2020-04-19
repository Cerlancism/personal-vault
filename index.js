//@ts-check

const fs = require('fs')
const express = require('express')

const { generateRandomHex, generateHash, getSaltedHash, encrypt, decrypt } = require('./crypto-utils')

const app = express()

const vaultFiles = fs.readdirSync("./vault")

/**
 * 
 * @param {string} target 
 * @param {string} key 
 */
function isValidKey(target, key)
{
    const salted = getSaltedHash(target, key)
    return vaultFiles.some(x => x == salted)
}


