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
    /** @type {Set<string>} */
    denyList: new Set(),

    /** @type {{ip: string, time: number}[]} */
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
    return res.contentType("text").status(403).send(message)
}

const app = express()

app.enable('trust proxy')

app.all("*", (req, res, next) =>
{
    // protocol check, from ie: glitch.com, if http, redirect to https,
    const protocol = req.get('X-Forwarded-Proto')
    if (!protocol)
    {
        return next();
    }
    if (protocol.indexOf("https") != -1)
    {
        return next()
    } else
    {
        const redirect = "https://" + req.hostname + req.url
        console.log("Redirecting to https: ", redirect)
        res.redirect(redirect);
    }
})

// Logging and rate limiting all accesses
app.all("*", (req, res, next) => 
{
    const limit = 5
    const interval = 10000
    const now = Date.now()

    log("ACCESS", "ip", req.ip, "params", JSON.stringify(req.params))

    context.accesses.push({ ip: req.ip, time: now })

    context.accesses = context.accesses.filter(x => now - x.time < interval)

    if (context.denyList.has(req.ip))
    {
        const lastAccesses = context.accesses.filter(x => x.ip === req.ip)
        if (lastAccesses.length < limit)
        {
            context.denyList.delete(req.ip)
        }
    }

    const accessesByIp = context.accesses.filter(x => x.ip === req.ip)
    if (accessesByIp.length > limit)
    {
        const start = accessesByIp[accessesByIp.length - limit - 1].time
        const end = accessesByIp[accessesByIp.length - 1].time
        if (end - start < interval)
        {
            context.denyList.add(req.ip)
        }
    }
    if (context.denyList.has(req.ip))
    {
        return deny(res)
    }
    next()
})

// Root page
app.get("/", (req, res) =>
{
    return res.send("<h1>Personal Vault</h1>")
})

// Open the a file in the vault
app.get("/open", (req, res, next) =>
{
    log("OPEN VAULT", "query", JSON.stringify(req.query))

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

// Take the KeySession target file
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

// Crypto utils with SHA1 and AES
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
    console.log("query", req.query)
    res.contentType("text").send(encrypt(req.query.data, req.query.key))
})

app.get("/decrypt", (req, res) => 
{
    res.contentType("text").send(decrypt(req.query.data, req.query.key))
})

// Deny all other accesses
app.all("/*", (req, res) =>
{
    return deny(res)
})

// Assume host platform (ie: glitch.com) will redirect to a https server
app.listen(8080)

