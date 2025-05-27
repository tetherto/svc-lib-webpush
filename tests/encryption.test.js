'use strict'

const { test } = require('brittle')
const { encrypt } = require('../lib/encryption')
const crypto = require('crypto')
const sinon = require('sinon')
const ece = require('http_ece')

test('encrypt', function (t) {
  const validUserPublicKey = 'BNcRdreALRFXTkOOUHK1EtK2wtaz5Ry4YfYCA_0QTpQtfZOc6rrVYU_PskdgIjyiqbK81hWj6hfxdFpDMF1cPU4'
  const validUserAuth = 'LsuUOBKVQRY6-l7_Ajo-Ag'
  const validPayload = 'Hello World!'
  const contentEncoding = 'aes128gcm'

  t.test('should validate userPublicKey', function (t) {
    t.exception(() => encrypt(null, validUserAuth, validPayload, contentEncoding),
      'should throw for null userPublicKey')

    t.exception(() => encrypt(undefined, validUserAuth, validPayload, contentEncoding),
      'should throw for undefined userPublicKey')

    t.exception(() => encrypt(123, validUserAuth, validPayload, contentEncoding),
      'should throw when userPublicKey is not a string')

    t.exception(() => encrypt('too-short', validUserAuth, validPayload, contentEncoding),
      'should throw when userPublicKey decodes to wrong length')
  })

  t.test('should validate userAuth', function (t) {
    t.exception(() => encrypt(validUserPublicKey, null, validPayload, contentEncoding),
      'should throw for null userAuth')

    t.exception(() => encrypt(validUserPublicKey, undefined, validPayload, contentEncoding),
      'should throw for undefined userAuth')

    t.exception(() => encrypt(validUserPublicKey, 123, validPayload, contentEncoding),
      'should throw when userAuth is not a string')

    t.exception(() => encrypt(validUserPublicKey, 'too-short', validPayload, contentEncoding),
      'should throw when userAuth decodes to wrong length')
  })

  t.test('should validate payload', function (t) {
    t.exception(() => encrypt(validUserPublicKey, validUserAuth, undefined, contentEncoding),
      'should throw for undefined payload')

    t.exception(() => encrypt(validUserPublicKey, validUserAuth, 123, contentEncoding),
      'should throw when payload is not a string or buffer')
  })

  t.test('should encrypt and return correct values', function (t) {
    const randomBytesMock = sinon.stub(crypto, 'randomBytes')
      .returns(Buffer.from('0123456789abcdef'))

    const localKeys = {
      publicKey: Buffer.from('localPublicKey'),
      privateKey: Buffer.from('localPrivateKey')
    }

    const mockCurve = {
      generateKeys: sinon.stub(),
      getPublicKey: sinon.stub().returns(localKeys.publicKey)
    }

    const createECDHStub = sinon.stub(crypto, 'createECDH').returns(mockCurve)

    const eceEncryptStub = sinon.stub(ece, 'encrypt')
      .returns(Buffer.from('encryptedPayload'))

    const result = encrypt(validUserPublicKey, validUserAuth, validPayload, contentEncoding)

    t.ok(createECDHStub.calledWith('prime256v1'), 'should create ECDH with prime256v1 curve')
    t.ok(mockCurve.generateKeys.calledOnce, 'should generate keys')

    t.ok(eceEncryptStub.calledOnce, 'should call ece.encrypt')
    t.is(eceEncryptStub.firstCall.args[0].toString(), validPayload, 'should pass payload to encrypt')

    // Check the options passed to ece.encrypt
    const eceOptions = eceEncryptStub.firstCall.args[1]
    t.is(eceOptions.version, contentEncoding, 'should pass content encoding')
    t.is(eceOptions.dh, validUserPublicKey, 'should pass user public key')
    t.is(eceOptions.privateKey, mockCurve, 'should pass local curve')
    t.is(eceOptions.authSecret, validUserAuth, 'should pass auth secret')

    // Check the returned values
    t.is(result.salt, 'MDEyMzQ1Njc4OWFiY2RlZg', 'should return salt')
    t.is(result.cipherText.toString(), 'encryptedPayload', 'should return cipherText')

    // Restore stubs
    randomBytesMock.restore()
    createECDHStub.restore()
    eceEncryptStub.restore()
  })
})
