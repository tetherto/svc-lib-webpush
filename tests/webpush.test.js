'use strict'

const { test } = require('brittle')
const sinon = require('sinon')
const WebPushService = require('../index')

test('WebPushService - constructor', function (t) {
  t.test('should throw error when missing VAPID config', function (t) {
    t.exception(() => {
      // eslint-disable-next-line no-new
      new WebPushService({})
    }, /ERR_INVALID_VAPID_CONFIG/, 'should throw when VAPID config is missing')

    t.exception(() => {
      // eslint-disable-next-line no-new
      new WebPushService({ vapid: {} })
    }, /ERR_INVALID_VAPID_CONFIG/, 'should throw when VAPID details are missing')

    t.exception(() => {
      // eslint-disable-next-line no-new
      new WebPushService({
        vapid: {
          subject: 'mailto:test@example.com',
          publicKey: 'publicKey'
          // No privateKey
        }
      })
    }, /ERR_INVALID_VAPID_CONFIG/, 'should throw when VAPID private key is missing')
  })

  t.test('should initialize with valid VAPID config', function (t) {
    const service = new WebPushService({
      vapid: {
        subject: 'mailto:test@example.com',
        publicKey: 'publicKey',
        privateKey: 'privateKey'
      }
    })

    t.is(service.vapid.subject, 'mailto:test@example.com', 'should store VAPID subject')
    t.is(service.vapid.publicKey, 'publicKey', 'should store VAPID public key')
    t.is(service.vapid.privateKey, 'privateKey', 'should store VAPID private key')
    t.is(service.defaultTTL, 4 * 60 * 60, 'should set default TTL to 4 hours')
  })

  t.test('should accept custom logger', function (t) {
    const customLogger = {
      info: sinon.spy(),
      error: sinon.spy()
    }

    const service = new WebPushService({
      vapid: {
        subject: 'mailto:test@example.com',
        publicKey: 'publicKey',
        privateKey: 'privateKey'
      },
      logger: customLogger
    })

    t.is(service.logger, customLogger, 'should use provided logger')

    service.logger.info('test message')
    t.ok(customLogger.info.calledWith('test message'), 'should use custom logger methods')
  })
})

test('WebPushService - isValidSubscription', function (t) {
  const service = new WebPushService({
    vapid: {
      subject: 'mailto:test@example.com',
      publicKey: 'publicKey',
      privateKey: 'privateKey'
    }
  })

  t.test('should validate correct subscription object', function (t) {
    const validSubscription = {
      endpoint: 'https://updates.push.services.mozilla.com/push/v1/123',
      keys: {
        p256dh: 'validPublicKey',
        auth: 'validAuthSecret'
      }
    }

    t.ok(service.isValidSubscription(validSubscription), 'should recognize valid subscription')
  })

  t.test('should reject invalid subscription objects', function (t) {
    t.not(service.isValidSubscription(null), 'should reject null')
    t.not(service.isValidSubscription({}), 'should reject empty object')
    t.not(service.isValidSubscription({ endpoint: 'endpoint' }), 'should reject when keys missing')
    t.not(service.isValidSubscription({
      endpoint: 'endpoint',
      keys: {}
    }), 'should reject when keys empty')

    t.not(service.isValidSubscription({
      endpoint: 'endpoint',
      keys: { p256dh: 'key' }
    }), 'should reject when auth missing')

    t.not(service.isValidSubscription({
      endpoint: 'endpoint',
      keys: { auth: 'secret' }
    }), 'should reject when p256dh missing')
  })
})

test('WebPushService - sendNotification', async function (t) {
  await t.test('should throw error when subscription is invalid', async function (t) {
    const service = new WebPushService({
      vapid: {
        subject: 'mailto:test@example.com',
        publicKey: 'validPublicKey',
        privateKey: 'validPrivateKey'
      }
    })

    await t.exception(() => service.sendNotification(null, 'test message'),
      /ERR_INVALID_SUBSCRIPTION/, 'should throw when subscription is null')

    await t.exception(() => service.sendNotification({}, 'test message'),
      /ERR_INVALID_SUBSCRIPTION/, 'should throw when subscription has no endpoint')

    await t.exception(() => service.sendNotification({ endpoint: 'endpoint' }, 'test message'),
      /ERR_INVALID_SUBSCRIPTION_FORMAT/, 'should throw when subscription is malformed')
  })

  await t.test('should correctly prepare and send push notification', async function (t) {
    const validSubscription = {
      endpoint: 'https://fcm.googleapis.com/fcm/send/123',
      keys: {
        p256dh: 'BJNGHXhPcYNbbdkdLp2Y7fZPcKV361Uu5R7iTD_WinsJbce6We-LRaz6Zkqb6ry_fBDdJscGolwRsagPsKvtbbM',
        auth: 'ySipQj7pD7t4TZOnan4Vow'
      }
    }

    const mockResponse = {
      statusCode: 201,
      body: Buffer.alloc(0)
    }

    const service = new WebPushService({
      vapid: {
        subject: 'mailto:test@example.com',
        publicKey: 'BBhRKWg5BokT9ph-AIcTaZHeysmA1pyVDp6nTCfnRJfvw6Optuw6_-p7uwmJUhcaTPvDtez-oSFvJ5VMRi8RRYM',
        privateKey: 'gOR77C2oeWh7O6ZPODGsUbHm3qt6xpHfpbJMu7BJmQk'
      }
    })

    // Mock the HTTP request function
    const sendPushRequestStub = sinon.stub(service, '_sendPushRequest').resolves(mockResponse)

    const result = await service.sendNotification(
      validSubscription,
      { title: 'Test', body: 'This is a test message' }
    )

    t.ok(sendPushRequestStub.calledOnce, 'should call _sendPushRequest')
    t.is(result.success, true, 'should return success flag')
    t.is(result.statusCode, 201, 'should return status code')

    const requestArgsEndpoint = sendPushRequestStub.firstCall.args[0]
    t.is(requestArgsEndpoint, validSubscription.endpoint, 'should use correct endpoint')

    const requestArgsHeaders = sendPushRequestStub.firstCall.args[2]
    t.ok(requestArgsHeaders.Authorization, 'should include Authorization header')
    t.is(requestArgsHeaders['Content-Encoding'], 'aes128gcm', 'should use aes128gcm content encoding')
    t.ok(requestArgsHeaders['Content-Length'] > 0, 'should set content length')
    t.is(requestArgsHeaders.TTL, 4 * 60 * 60, 'should set default TTL')
    t.is(requestArgsHeaders.Urgency, 'normal', 'should set default urgency')

    sendPushRequestStub.restore()
  })

  await t.test('should apply custom TTL option', async function (t) {
    const validSubscription = {
      endpoint: 'https://fcm.googleapis.com/fcm/send/123',
      keys: {
        p256dh: 'BJNGHXhPcYNbbdkdLp2Y7fZPcKV361Uu5R7iTD_WinsJbce6We-LRaz6Zkqb6ry_fBDdJscGolwRsagPsKvtbbM',
        auth: 'ySipQj7pD7t4TZOnan4Vow'
      }
    }

    const service = new WebPushService({
      vapid: {
        subject: 'mailto:test@example.com',
        publicKey: 'BBhRKWg5BokT9ph-AIcTaZHeysmA1pyVDp6nTCfnRJfvw6Optuw6_-p7uwmJUhcaTPvDtez-oSFvJ5VMRi8RRYM',
        privateKey: 'gOR77C2oeWh7O6ZPODGsUbHm3qt6xpHfpbJMu7BJmQk'
      }
    })

    // Mock the HTTP request function
    const sendPushRequestStub = sinon.stub(service, '_sendPushRequest').resolves({
      statusCode: 201,
      body: Buffer.alloc(0)
    })

    const customTTL = 60 * 60 // 1 hour
    await service.sendNotification(
      validSubscription,
      'Test message',
      { TTL: customTTL, urgency: 'high' }
    )

    const requestArgsHeaders = sendPushRequestStub.firstCall.args[2]
    t.is(requestArgsHeaders.TTL, customTTL, 'should use custom TTL')
    t.is(requestArgsHeaders.Urgency, 'high', 'should use custom urgency')

    sendPushRequestStub.restore()
  })
})

test('WebPushService - static generateVapidKeys', function (t) {
  t.test('should generate VAPID keys', function (t) {
    const keys = WebPushService.generateVapidKeys()

    t.ok(keys.publicKey, 'should return public key')
    t.ok(keys.privateKey, 'should return private key')
    t.is(typeof keys.publicKey, 'string', 'public key should be string')
    t.is(typeof keys.privateKey, 'string', 'private key should be string')
  })
})
