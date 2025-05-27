'use strict'

const CONTENT_ENCODING = Object.freeze({
  AES_GCM: 'aesgcm',
  AES_128_GCM: 'aes128gcm'
})

const URGENCY = Object.freeze({
  VERY_LOW: 'very-low',
  LOW: 'low',
  NORMAL: 'normal',
  HIGH: 'high'
})

module.exports = {
  CONTENT_ENCODING,
  URGENCY
}
