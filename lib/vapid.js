'use strict'

const crypto = require('crypto')
const asn1 = require('asn1.js')
const jws = require('jws')
const { URL } = require('url')
const { validate } = require('./base64')

/**
 * DEFAULT_EXPIRATION is set to seconds in 12 hours
 */
const DEFAULT_EXPIRATION_SECONDS = 12 * 60 * 60

// Maximum expiration is 24 hours according. (See VAPID spec)
const MAX_EXPIRATION_SECONDS = 24 * 60 * 60

const ECPrivateKeyASN = asn1.define('ECPrivateKey', function () {
  this.seq().obj(
    this.key('version').int(),
    this.key('privateKey').octstr(),
    this.key('parameters').explicit(0).objid()
      .optional(),
    this.key('publicKey').explicit(1).bitstr()
      .optional()
  )
})

function toPEM (key) {
  return ECPrivateKeyASN.encode({
    version: 1,
    privateKey: key,
    parameters: [1, 2, 840, 10045, 3, 1, 7] // prime256v1
  }, 'pem', {
    label: 'EC PRIVATE KEY'
  })
}

function generateVAPIDKeys () {
  const curve = crypto.createECDH('prime256v1')
  curve.generateKeys()

  let publicKeyBuffer = curve.getPublicKey()
  let privateKeyBuffer = curve.getPrivateKey()

  // Occassionally the keys will not be padded to the correct lengh resulting
  // in errors, hence this padding.
  // See https://github.com/web-push-libs/web-push/issues/295 for history.
  if (privateKeyBuffer.length < 32) {
    const padding = Buffer.alloc(32 - privateKeyBuffer.length)
    padding.fill(0)
    privateKeyBuffer = Buffer.concat([padding, privateKeyBuffer])
  }

  if (publicKeyBuffer.length < 65) {
    const padding = Buffer.alloc(65 - publicKeyBuffer.length)
    padding.fill(0)
    publicKeyBuffer = Buffer.concat([padding, publicKeyBuffer])
  }

  return {
    publicKey: publicKeyBuffer.toString('base64url'),
    privateKey: privateKeyBuffer.toString('base64url')
  }
}

function validateSubject (subject, logger) {
  if (!subject) {
    throw new Error('ERR_VAPID_SUBJECT_MISSING')
  }

  if (typeof subject !== 'string' || subject.length === 0) {
    throw new Error('ERR_VAPID_SUBJECT_INVALID')
  }

  let subjectParseResult = null
  try {
    subjectParseResult = new URL(subject)
  } catch (err) {
    throw new Error('ERR_VAPID_SUBJECT_INVALID_URL')
  }
  if (!['https:', 'mailto:'].includes(subjectParseResult.protocol)) {
    throw new Error('ERR_VAPID_SUBJECT_PROTOCOL_INVALID')
  }
  if (subjectParseResult.hostname === 'localhost') {
    logger.warn('Vapid subject points to a localhost web URI, which is unsupported by ' +
      'Apple\'s push notification server and will result in a BadJwtToken error when ' +
      'sending notifications.')
  }
}

function validatePublicKey (publicKey) {
  if (!publicKey) {
    throw new Error('ERR_VAPID_PUBLIC_KEY_MISSING')
  }

  if (typeof publicKey !== 'string') {
    throw new Error('ERR_VAPID_PUBLIC_KEY_INVALID')
  }

  if (!validate(publicKey)) {
    throw new Error('ERR_VAPID_PUBLIC_KEY_INVALID_FORMAT')
  }

  publicKey = Buffer.from(publicKey, 'base64url')

  if (publicKey.length !== 65) {
    throw new Error('ERR_VAPID_PUBLIC_KEY_INVALID_LENGTH')
  }
}

function validatePrivateKey (privateKey) {
  if (!privateKey) {
    throw new Error('ERR_VAPID_PRIVATE_KEY_MISSING')
  }

  if (typeof privateKey !== 'string') {
    throw new Error('ERR_VAPID_PRIVATE_KEY_INVALID')
  }

  if (!validate(privateKey)) {
    throw new Error('ERR_VAPID_PRIVATE_KEY_INVALID_FORMAT')
  }

  privateKey = Buffer.from(privateKey, 'base64url')

  if (privateKey.length !== 32) {
    throw new Error('ERR_VAPID_PRIVATE_KEY_INVALID_LENGTH')
  }
}

/**
 * Given the number of seconds calculates
 * the expiration in the future by adding the passed `numSeconds`
 * with the current seconds from Unix Epoch
 *
 * @param {Number} numSeconds Number of seconds to be added
 * @return {Number} Future expiration in seconds
 */
function getFutureExpirationTimestamp (numSeconds) {
  const futureExp = new Date()
  futureExp.setSeconds(futureExp.getSeconds() + numSeconds)
  return Math.floor(futureExp.getTime() / 1000)
}

/**
 * Validates the Expiration Header based on the VAPID Spec
 * Throws error of type `Error` if the expiration is not validated
 *
 * @param {Number} expiration Expiration seconds from Epoch to be validated
 */
function validateExpiration (expiration) {
  if (!Number.isInteger(expiration)) {
    throw new Error('ERR_VAPID_EXPIRATION_INVALID_TYPE')
  }

  if (expiration < 0) {
    throw new Error('ERR_VAPID_EXPIRATION_NEGATIVE')
  }

  // Roughly checks the time of expiration, since the max expiration can be ahead
  // of the time than at the moment the expiration was generated
  const maxExpirationTimestamp = getFutureExpirationTimestamp(MAX_EXPIRATION_SECONDS)

  if (expiration >= maxExpirationTimestamp) {
    throw new Error('ERR_VAPID_EXPIRATION_TOO_LONG')
  }
}

/**
 * This method takes the required VAPID parameters and returns the required
 * header to be added to a Web Push Protocol Request.
 * @param  {string} audience        This must be the origin of the push service.
 * @param  {string} subject         This should be a URL or a 'mailto:' email
 * address.
 * @param  {string} publicKey       The VAPID public key.
 * @param  {string} privateKey      The VAPID private key.
 * @param  {string} contentEncoding The contentEncoding type.
 * @param  {integer} [expiration]   The expiration of the VAPID JWT.
 * @param  {Object} [logger]        An optional logger object with a warn method.
 * @return {Object}                 Returns an Object with the Authorization and
 * 'Crypto-Key' values to be used as headers.
 */
function getVapidHeaders (audience, subject, publicKey, privateKey, contentEncoding, expiration, logger = { warn: () => {} }) {
  if (!audience) {
    throw new Error('ERR_VAPID_AUDIENCE_MISSING')
  }

  if (typeof audience !== 'string' || audience.length === 0) {
    throw new Error('ERR_VAPID_AUDIENCE_INVALID')
  }

  try {
    new URL(audience) // eslint-disable-line no-new
  } catch (err) {
    throw new Error('ERR_VAPID_AUDIENCE_INVALID_URL')
  }

  validateSubject(subject, logger)
  validatePublicKey(publicKey)
  validatePrivateKey(privateKey)

  privateKey = Buffer.from(privateKey, 'base64url')

  if (expiration) {
    validateExpiration(expiration)
  } else {
    expiration = getFutureExpirationTimestamp(DEFAULT_EXPIRATION_SECONDS)
  }

  const header = {
    typ: 'JWT',
    alg: 'ES256'
  }

  const jwtPayload = {
    aud: audience,
    exp: expiration,
    sub: subject
  }

  const jwt = jws.sign({
    header,
    payload: jwtPayload,
    privateKey: toPEM(privateKey)
  })

  if (contentEncoding === 'aes128gcm') {
    return {
      Authorization: 'vapid t=' + jwt + ', k=' + publicKey
    }
  }
  if (contentEncoding === 'aesgcm') {
    return {
      Authorization: 'WebPush ' + jwt,
      'Crypto-Key': 'p256ecdsa=' + publicKey
    }
  }

  throw new Error('ERR_VAPID_CONTENT_ENCODING_UNSUPPORTED')
}

module.exports = {
  generateVAPIDKeys,
  getVapidHeaders,
  validateSubject,
  validatePublicKey,
  validatePrivateKey,
  validateExpiration,
  getFutureExpirationTimestamp
}
