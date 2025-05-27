'use strict'

const crypto = require('crypto')
const ece = require('http_ece')

const encrypt = function (userPublicKey, userAuth, payload, contentEncoding) {
  if (!userPublicKey) {
    throw new Error('ERR_ENCRYPTION_USER_PUBLIC_KEY_MISSING')
  }

  if (typeof userPublicKey !== 'string') {
    throw new Error('ERR_ENCRYPTION_USER_PUBLIC_KEY_INVALID')
  }

  if (Buffer.from(userPublicKey, 'base64url').length !== 65) {
    throw new Error('ERR_ENCRYPTION_USER_PUBLIC_KEY_INVALID_LENGTH')
  }

  if (!userAuth) {
    throw new Error('ERR_ENCRYPTION_USER_AUTH_MISSING')
  }

  if (typeof userAuth !== 'string') {
    throw new Error('ERR_ENCRYPTION_USER_AUTH_INVALID')
  }

  if (Buffer.from(userAuth, 'base64url').length < 16) {
    throw new Error('ERR_ENCRYPTION_USER_AUTH_INVALID_LENGTH')
  }

  if (typeof payload !== 'string' && !Buffer.isBuffer(payload)) {
    throw new Error('ERR_ENCRYPTION_PAYLOAD_INVALID')
  }

  if (typeof payload === 'string' || payload instanceof String) {
    payload = Buffer.from(payload)
  }

  const localCurve = crypto.createECDH('prime256v1')
  const localPublicKey = localCurve.generateKeys()

  const salt = crypto.randomBytes(16).toString('base64url')

  const cipherText = ece.encrypt(payload, {
    version: contentEncoding,
    dh: userPublicKey,
    privateKey: localCurve,
    salt,
    authSecret: userAuth
  })

  return {
    localPublicKey,
    salt,
    cipherText
  }
}

module.exports = { encrypt }
