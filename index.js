//@ts-check

const fs = require('fs')
const express = require('express')

const { generateRandomHex, generateHash, getSaltedHash, encrypt, decrypt } = require('./crypto-utils')

const app = express()
