'use strict'

const { test } = require('brittle')
const vapid = require('../lib/vapid')
const crypto = require('crypto')
const sinon = require('sinon')
const jws = require('jws')

test('generateVAPIDKeys', function (t) {
  t.test('should generate VAPID keys with correct format', function (t) {
    const keys = vapid.generateVAPIDKeys()

    t.ok(keys.publicKey, 'should have publicKey')
    t.ok(keys.privateKey, 'should have privateKey')

    t.is(typeof keys.publicKey, 'string', 'publicKey should be string')
    t.is(typeof keys.privateKey, 'string', 'privateKey should be string')

    // Check that we can decode the keys
    const publicKeyBuffer = Buffer.from(keys.publicKey, 'base64url')
    const privateKeyBuffer = Buffer.from(keys.privateKey, 'base64url')

    t.is(publicKeyBuffer.length, 65, 'publicKey should be 65 bytes when decoded')
    t.is(privateKeyBuffer.length, 32, 'privateKey should be 32 bytes when decoded')
  })

  t.test('should use crypto properly', function (t) {
    const mockCurve = {
      generateKeys: sinon.stub(),
      getPublicKey: sinon.stub().returns(Buffer.from('publicKey')),
      getPrivateKey: sinon.stub().returns(Buffer.from('privateKey'))
    }

    const createECDHStub = sinon.stub(crypto, 'createECDH').returns(mockCurve)

    vapid.generateVAPIDKeys()

    t.ok(createECDHStub.calledWith('prime256v1'), 'should use prime256v1 curve')
    t.ok(mockCurve.generateKeys.calledOnce, 'should call generateKeys')
    t.ok(mockCurve.getPublicKey.calledOnce, 'should call getPublicKey')
    t.ok(mockCurve.getPrivateKey.calledOnce, 'should call getPrivateKey')

    createECDHStub.restore()
  })

  t.test('should handle key padding properly', function (t) {
    const mockCurve = {
      generateKeys: sinon.stub(),
      getPublicKey: sinon.stub().returns(Buffer.from('short-public-key')),
      getPrivateKey: sinon.stub().returns(Buffer.from('short-private-key'))
    }

    const createECDHStub = sinon.stub(crypto, 'createECDH').returns(mockCurve)

    const keys = vapid.generateVAPIDKeys()

    t.ok(createECDHStub.calledWith('prime256v1'), 'should use prime256v1 curve')

    // Check that keys were padded properly
    const publicKeyBuffer = Buffer.from(keys.publicKey, 'base64url')
    const privateKeyBuffer = Buffer.from(keys.privateKey, 'base64url')

    t.is(publicKeyBuffer.length, 65, 'publicKey should be padded to 65 bytes')
    t.is(privateKeyBuffer.length, 32, 'privateKey should be padded to 32 bytes')

    createECDHStub.restore()
  })
})

test('validateSubject', function (t) {
  t.test('should accept valid mailto: and https: URLs', function (t) {
    try {
      vapid.validateSubject('mailto:test@example.com')
      vapid.validateSubject('https://example.com')
      t.pass('should accept valid mailto and https URLs')
    } catch (error) {
      t.fail('should not throw for valid subjects')
    }
  })

  t.test('should reject invalid subject values', function (t) {
    t.exception(() => vapid.validateSubject(), 'should throw when subject is undefined')
    t.exception(() => vapid.validateSubject(''), 'should throw when subject is empty')
    t.exception(() => vapid.validateSubject(123), 'should throw when subject is not a string')
    t.exception(() => vapid.validateSubject('invalid-url'), 'should throw when subject is not a URL')
    t.exception(() => vapid.validateSubject('http://example.com'), 'should throw when subject is not https or mailto')

    // Verify that localhost URLs log a warning (but don't throw)
    const consoleWarnStub = sinon.stub(console, 'warn')
    vapid.validateSubject('https://localhost/push')
    t.ok(consoleWarnStub.calledOnce, 'should warn about localhost')
    consoleWarnStub.restore()
  })
})

test('validatePublicKey', function (t) {
  t.test('should accept valid public key', function (t) {
    const validKey = 'BDd3_hVL9fZi9Ybo2UUzA284WG5FZR30_95YeZJsiApwXKpNcF1rRPF3foIiBHXRdJI2Qhumhf6_LFTeZaNndIo'
    try {
      vapid.validatePublicKey(validKey)
      t.pass()
    } catch (error) {
      t.fail()
    }
  })

  t.test('should reject invalid public key', function (t) {
    t.exception(() => vapid.validatePublicKey(), 'should throw when key is undefined')
    t.exception(() => vapid.validatePublicKey(''), 'should throw when key is empty')
    t.exception(() => vapid.validatePublicKey(123), 'should throw when key is not a string')
    t.exception(() => vapid.validatePublicKey('invalid=key'), 'should throw when key is not base64url')

    // Key with incorrect length
    t.exception(() => vapid.validatePublicKey('tooshort'), 'should throw when key is too short')
  })
})

test('validatePrivateKey', function (t) {
  t.test('should accept valid private key', function (t) {
    const validKey = 'C2S4tCp8iERrhHCKqzaIyEjgm-XDIJ1Y4fS-qtctswI'
    try {
      vapid.validatePrivateKey(validKey)
      t.pass()
    } catch (error) {
      t.fail()
    }
  })

  t.test('should reject invalid private key', function (t) {
    t.exception(() => vapid.validatePrivateKey(), 'should throw when key is undefined')
    t.exception(() => vapid.validatePrivateKey(''), 'should throw when key is empty')
    t.exception(() => vapid.validatePrivateKey(123), 'should throw when key is not a string')
    t.exception(() => vapid.validatePrivateKey('invalid=key'), 'should throw when key is not base64url')

    // Key with incorrect length
    t.exception(() => vapid.validatePrivateKey('tooshort'), 'should throw when key is too short')
  })
})

test('getFutureExpirationTimestamp', function (t) {
  t.test('should calculate correct future timestamp', function (t) {
    const now = Math.floor(Date.now() / 1000)

    const timestamp = vapid.getFutureExpirationTimestamp(3600) // 1 hour in future

    // Allow for small differences due to test execution time
    t.ok(timestamp >= now + 3600 - 1, 'should be at least 1 hour in future')
    t.ok(timestamp <= now + 3600 + 1, 'should not be more than 1 hour + 1s in future')
  })
})

test('validateExpiration', function (t) {
  t.test('should accept valid expiration', function (t) {
    const now = Math.floor(Date.now() / 1000)
    try {
      vapid.validateExpiration(now + 3600)
      t.pass()
    } catch (error) {
      t.fail()
    }
  })

  t.test('should reject invalid expiration', function (t) {
    t.exception(() => vapid.validateExpiration('not-a-number'), 'should throw when expiration is not a number')
    t.exception(() => vapid.validateExpiration(3.14), 'should throw when expiration is not an integer')
    t.exception(() => vapid.validateExpiration(-1), 'should throw when expiration is negative')

    const now = Math.floor(Date.now() / 1000)
    t.exception(() => vapid.validateExpiration(now + 25 * 3600), 'should throw when expiration is > 24 hours')
  })
})

test('getVapidHeaders', function (t) {
  t.test('should generate headers for aes128gcm content encoding', function (t) {
    const audience = 'https://fcm.googleapis.com'
    const subject = 'mailto:test@example.com'
    const publicKey = 'BDd3_hVL9fZi9Ybo2UUzA284WG5FZR30_95YeZJsiApwXKpNcF1rRPF3foIiBHXRdJI2Qhumhf6_LFTeZaNndIo'
    const privateKey = 'C2S4tCp8iERrhHCKqzaIyEjgm-XDIJ1Y4fS-qtctswI'
    const contentEncoding = 'aes128gcm'

    const jwsStub = sinon.stub(jws, 'sign').returns('test.jwt.signature')

    const headers = vapid.getVapidHeaders(
      audience,
      subject,
      publicKey,
      privateKey,
      contentEncoding
    )

    t.is(typeof headers, 'object', 'should return an object')
    t.is(headers.Authorization, 'vapid t=test.jwt.signature, k=' + publicKey, 'should format aes128gcm auth header correctly')
    t.not(headers['Crypto-Key'], 'should not include Crypto-Key header for aes128gcm')

    jwsStub.restore()
  })

  t.test('should generate headers for aesgcm content encoding', function (t) {
    const audience = 'https://fcm.googleapis.com'
    const subject = 'mailto:test@example.com'
    const publicKey = 'BDd3_hVL9fZi9Ybo2UUzA284WG5FZR30_95YeZJsiApwXKpNcF1rRPF3foIiBHXRdJI2Qhumhf6_LFTeZaNndIo'
    const privateKey = 'C2S4tCp8iERrhHCKqzaIyEjgm-XDIJ1Y4fS-qtctswI'
    const contentEncoding = 'aesgcm'

    const jwsStub = sinon.stub(jws, 'sign').returns('test.jwt.signature')

    const headers = vapid.getVapidHeaders(
      audience,
      subject,
      publicKey,
      privateKey,
      contentEncoding
    )

    t.is(typeof headers, 'object', 'should return an object')
    t.is(headers.Authorization, 'WebPush test.jwt.signature', 'should format aesgcm auth header correctly')
    t.is(headers['Crypto-Key'], 'p256ecdsa=' + publicKey, 'should include Crypto-Key header for aesgcm')

    jwsStub.restore()
  })

  t.test('should reject invalid content encoding', function (t) {
    const audience = 'https://fcm.googleapis.com'
    const subject = 'mailto:test@example.com'
    const publicKey = 'BDd3_hVL9fZi9Ybo2UUzA284WG5FZR30_95YeZJsiApwXKpNcF1rRPF3foIiBHXRdJI2Qhumhf6_LFTeZaNndIo'
    const privateKey = 'C2S4tCp8iERrhHCKqzaIyEjgm-XDIJ1Y4fS-qtctswI'
    const contentEncoding = 'invalid-encoding'

    t.exception(
      () => vapid.getVapidHeaders(audience, subject, publicKey, privateKey, contentEncoding),
      'should throw for invalid encoding'
    )
  })

  t.test('should validate all inputs', function (t) {
    const publicKey = 'BDd3_hVL9fZi9Ybo2UUzA284WG5FZR30_95YeZJsiApwXKpNcF1rRPF3foIiBHXRdJI2Qhumhf6_LFTeZaNndIo'
    const privateKey = 'C2S4tCp8iERrhHCKqzaIyEjgm-XDIJ1Y4fS-qtctswI'
    const contentEncoding = 'aes128gcm'

    t.exception(
      () => vapid.getVapidHeaders(null, 'mailto:test@example.com', publicKey, privateKey, contentEncoding),
      'should throw for null audience'
    )

    t.exception(
      () => vapid.getVapidHeaders('invalid-url', 'mailto:test@example.com', publicKey, privateKey, contentEncoding),
      'should throw for invalid audience'
    )

    t.exception(
      () => vapid.getVapidHeaders('https://example.com', null, publicKey, privateKey, contentEncoding),
      'should throw for null subject'
    )

    t.exception(
      () => vapid.getVapidHeaders('https://example.com', 'mailto:test@example.com', null, privateKey, contentEncoding),
      'should throw for null public key'
    )

    t.exception(
      () => vapid.getVapidHeaders('https://example.com', 'mailto:test@example.com', publicKey, null, contentEncoding),
      'should throw for null private key'
    )
  })

  t.test('should create proper JWT payload', function (t) {
    const audience = 'https://fcm.googleapis.com'
    const subject = 'mailto:test@example.com'
    const publicKey = 'BDd3_hVL9fZi9Ybo2UUzA284WG5FZR30_95YeZJsiApwXKpNcF1rRPF3foIiBHXRdJI2Qhumhf6_LFTeZaNndIo'
    const privateKey = 'C2S4tCp8iERrhHCKqzaIyEjgm-XDIJ1Y4fS-qtctswI'
    const contentEncoding = 'aes128gcm'
    const expiration = Math.floor(Date.now() / 1000) + 3600 // 1 hour from now

    const jwsSignStub = sinon.stub(jws, 'sign')

    vapid.getVapidHeaders(
      audience,
      subject,
      publicKey,
      privateKey,
      contentEncoding,
      expiration
    )

    t.ok(jwsSignStub.calledOnce, 'should call jws.sign')

    const payload = jwsSignStub.firstCall.args[0].payload
    t.is(payload.aud, audience, 'should set audience in JWT')
    t.is(payload.sub, subject, 'should set subject in JWT')
    t.is(payload.exp, expiration, 'should set expiration in JWT')

    jwsSignStub.restore()
  })
})
