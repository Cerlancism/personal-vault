//@ts-check

const fs = require('fs')
const express = require('express')

const { generateRandomHex, generateHash, getSaltedHash, encrypt, decrypt } = require('./crypto-utils')

class KeySession
{
    /**
     * 
     * @param {string} target
     * @param {string?} key 
     * @param {number} ttl 
     */
    constructor(target, key, ttl)
    {
        this.target = target
        this.key = key
        setTimeout(() => this.expire(), ttl)
    }

    expire()
    {
        this.key = null
        if (context.keySession === this)
        {
            context.keySession = null
        }
    }
}

const context =
{
    denied: false,

    /** @type {Date[]} */
    accesses: [],

    /** @type {KeySession?} */
    keySession: null,
}

function getVault()
{
    return fs.readdirSync("./vault")
}

/**
 * 
 * @param {string} source 
 * @param  {...any} messages 
 */
function log(source, ...messages)
{
    console.log(`${new Date().toUTCString()} [${source}] ${messages.join(" ")}`)
}
/**
 * 
 * @param {string} target 
 * @param {string} key 
 */
function isValidKey(target, key)
{
    const vaultFiles = getVault()
    const salted = getSaltedHash(target, key)
    return vaultFiles.some(x => x == salted)
}

/**
 * 
 * @param {import('express').Response} res 
 * @param {any} message 
 */
function deny(res, message = "Access Denied")
{
    return res.contentType("text").status(401).send(message)
}

const app = express()

app.all("*", (req, res, next) =>
{
    // protocol check, from ie: glitch.com, if http, redirect to https,
    const protocol = req.get('X-Forwarded-Proto')
    if (!protocol)
    {
        console.log("X-Forwarded-Proto missing")
        return next();
    }
    if (protocol.indexOf("https") != -1)
    {
        return next()
    } else
    {
        const redirect = "https://" + req.hostname + req.url
        console.log("Redirecting to https: " , redirect)
        res.redirect(redirect);
    }
})

// Logging and rate limiting all accesses
app.use("*", (req, res, next) => 
{
    log("ACCESS", "params", JSON.stringify(req.params))
    context.accesses.push(new Date())
    if (context.accesses.length > 1100)
    {
        context.accesses = context.accesses.slice(100)
    }
    if (context.accesses.length > 10)
    {
        const start = context.accesses[context.accesses.length - 11]
        const end = context.accesses[context.accesses.length - 1]
        if (end.getTime() - start.getTime() < 10000)
        {
            context.denied = true
        }
        else
        {
            context.denied = false
        }
        if (context.denied)
        {
            context.accesses.shift()
        }
    }
    if (context.denied)
    {
        return deny(res)
    }
    next()
})

// Root page
app.get("/", (req, res) =>
{
    if (context.denied)
    {
        return deny(res)
    }
    return res.send("<h1>Personal Vault</h1>")
})

// Open the a file in the vault
app.get("/open", (req, res, next) =>
{
    log("OPEN VAULT", "query", JSON.stringify(req.query))

    if (context.denied)
    {
        return deny(res)
    }

    const { key, target, ttl } = req.query

    if (!key || !target)
    {
        return deny(res)
    }
    if (!isValidKey(target, key))
    {
        return deny(res)
    }

    const ttlActual = isNaN(ttl) ? 60000 : Number(ttl)

    context.keySession = new KeySession(target, key, ttlActual)

    return res.contentType("text").send("ok, ttl=" + ttlActual)
})

app.get("/take", (req, res) =>
{
    if (!context.keySession || !context.keySession.key)
    {
        return deny(res)
    }
    const { target: sessionTarget, key } = context.keySession
    context.keySession.expire()
    const { target } = req.query
    if (target !== sessionTarget)
    {
        return deny(res)
    }
    const file = fs.readFileSync("./vault/" + getSaltedHash(target, key)).toString('utf-8')
    return res.contentType("text").send(decrypt(file, key))
})

app.get("/randomhex", (req, res) =>
{
    res.contentType("text").send(generateRandomHex(isNaN(req.query.length) ? 32 : Number(req.query.length)))
})

app.get("/hash", (req, res) =>
{
    res.contentType("text").send(generateHash(req.query.input))
})

app.get("/encrypt", (req, res) =>
{
    res.contentType("text").send(encrypt(req.query.data, req.query.key))
})

app.get("/decrypt", (req, res) => 
{
    res.contentType("text").send(decrypt(req.query.data, req.query.key))
})

app.all("/*", (req, res) =>
{
    return deny(res)
})

// Assume host platform (ie: glitch.com) will redirect to a https server
app.listen(8080)

