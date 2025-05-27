'use strict'

const { test } = require('brittle')
const urlBase64Helper = require('../lib/base64')

test('validate', function (t) {
  t.test('should return true for valid base64url strings', function (t) {
    t.is(urlBase64Helper.validate('abc123'), true, 'should validate alphanumeric string')
    t.is(urlBase64Helper.validate('abc-123'), true, 'should validate with hyphens')
    t.is(urlBase64Helper.validate('abc_123'), true, 'should validate with underscores')

    // Common base64url examples
    t.is(urlBase64Helper.validate('SGVsbG8gV29ybGQ'), true, 'should validate unpadded base64url')
    t.is(urlBase64Helper.validate('BNcRdreALRFXTkOOUHK1EtK2wtaz5Ry4YfYCA_0QTpQtfZOc6rrVYU_PskdgIjyiqbK81hWj6hfxdFpDMF1cPU4'), true, 'should validate long key')
  })

  t.test('should return false for invalid base64url strings', function (t) {
    t.is(urlBase64Helper.validate('abc=123'), false, 'should reject padding characters')
    t.is(urlBase64Helper.validate('abc+123'), false, 'should reject plus signs')
    t.is(urlBase64Helper.validate('abc/123'), false, 'should reject slashes')
    t.is(urlBase64Helper.validate('abc 123'), false, 'should reject spaces')
    t.is(urlBase64Helper.validate('abc!123'), false, 'should reject special characters')

    // Non-string values should fail
    t.is(urlBase64Helper.validate(null), false, 'should reject null')
    t.is(urlBase64Helper.validate(undefined), false, 'should reject undefined')
    t.is(urlBase64Helper.validate(123), false, 'should reject numbers')
    t.is(urlBase64Helper.validate({}), false, 'should reject objects')
  })
})
