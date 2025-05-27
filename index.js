'use strict'

const HttpFacility = require('bfx-facs-http')
const ReadyResource = require('ready-resource')
const { encrypt } = require('./lib/encryption')
const { promiseFlat } = require('lib-js-util-promise')
const { CONTENT_ENCODING, URGENCY } = require('./lib/constants')
const { getVapidHeaders, generateVAPIDKeys } = require('./lib/vapid')

class WebPushService extends ReadyResource {
  /**
   * Create a new WebPushService instance
   * @param {Object} opts - Configuration options
   * @param {Object} opts.vapid - VAPID credentials
   * @param {string} opts.vapid.subject - VAPID subject (mailto: or URL)
   * @param {string} opts.vapid.publicKey - VAPID public key
   * @param {string} opts.vapid.privateKey - VAPID private key
   * @param {Object} [opts.logger=null] - Logger instance with info and error methods
   */
  constructor (opts = {}) {
    super()

    if (!opts.vapid || !opts.vapid.subject || !opts.vapid.publicKey || !opts.vapid.privateKey) {
      throw new Error('ERR_VAPID_CONFIG_MISSING')
    }

    this.vapid = opts.vapid
    this.logger = opts.logger || {
      info: () => { },
      error: () => { }
    }

    this.defaultTTL = 4 * 60 * 60
    this.httpFac = new HttpFacility(this, {}, {})
  }

  async _open () {
    // Start the HTTP facility
    await this.httpFac.start()
  }

  async _close () {
    if (this.httpFac) {
      await this.httpFac.stop()
    }
  }

  /**
   * Send a push notification to a subscription
   * @param {Object} subscription - PushSubscription object
   * @param {Object|string} payload - Notification data to send (will be stringified if object)
   * @param {Object} [options] - Additional options
   * @param {number} [options.TTL=7200] - Time to live in seconds
   * @returns {Promise<Object>} Response data
   * @throws {Error} When sending fails
   */
  async sendNotification (subscription, payload, options = {}) {
    if (!subscription || !subscription.endpoint) {
      throw new Error('ERR_INVALID_SUBSCRIPTION')
    }

    if (!this.isValidSubscription(subscription)) {
      throw new Error('ERR_INVALID_SUBSCRIPTION_FORMAT')
    }

    const payloadString = typeof payload === 'object' ? JSON.stringify(payload) : payload

    const contentEncoding = CONTENT_ENCODING.AES_128_GCM
    const encryptedPayload = encrypt(subscription.keys.p256dh, subscription.keys.auth, payloadString, contentEncoding)

    const parsedUrl = new URL(subscription.endpoint)
    const audience = parsedUrl.protocol + '//' + parsedUrl.host
    const vapidHeaders = getVapidHeaders(
      audience,
      this.vapid.subject,
      this.vapid.publicKey,
      this.vapid.privateKey,
      contentEncoding,
      null,
      this.logger
    )

    const urgency = options.urgency || URGENCY.NORMAL

    // Send the push notification
    this.logger.info(`Sending push notification to ${subscription.endpoint}`)

    const headers = {
      Authorization: vapidHeaders.Authorization,
      'Content-Length': encryptedPayload.cipherText.length,
      'Content-Type': 'application/octet-stream',
      'Content-Encoding': contentEncoding,
      Urgency: urgency,
      TTL: options.TTL || this.defaultTTL
    }

    const result = await this._sendPushRequest(
      subscription.endpoint,
      encryptedPayload.cipherText,
      headers
    )

    return {
      success: true,
      statusCode: result.statusCode,
      body: result.body
    }
  }

  /**
   * Send HTTP request to the push service using HttpFacility
   * @private
   * @param {string} endpoint - Push subscription endpoint
   * @param {Buffer} body - Encrypted payload
   * @param {Object} headers - HTTP headers including VAPID authentication
   * @returns {Promise<Object>} HTTP response
   */
  async _sendPushRequest (endpoint, body, headers) {
    const { promise, resolve, reject } = promiseFlat()

    try {
      const options = {
        method: 'POST',
        headers,
        body,
        encoding: {
          req: 'raw',
          res: 'raw'
        }
      }
      const res = await this.httpFac.request(endpoint, options)

      let responseData = Buffer.alloc(0)
      res.body.on('data', chunk => {
        responseData = Buffer.concat([responseData, chunk])
      })

      res.body.on('end', () => {
        resolve({ statusCode: 200, body: responseData })
      })

      res.body.on('error', (err) => {
        reject(err)
      })
    } catch (err) {
      reject(err)
    }

    return promise
  }

  /**
   * Verify subscription object is valid
   * @param {Object} subscription - PushSubscription object to verify
   * @returns {boolean} Whether subscription is valid
   */
  isValidSubscription (subscription) {
    return subscription &&
      subscription.endpoint &&
      subscription.keys &&
      subscription.keys.p256dh &&
      subscription.keys.auth
  }

  /**
   *
   * @returns {Object} Generated VAPID keys with public and private keys
   * @throws {Error} If key generation fails
   * @description Generates a new set of VAPID keys for use in push notifications.
   * The keys are returned in a format suitable for use with the WebPushService.
   * The keys include a public key, and private key.
   * This method is useful for initializing the service with new keys.
   */
  static generateVapidKeys () {
    return generateVAPIDKeys()
  }
}

module.exports = WebPushService
