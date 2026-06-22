import sinon from 'sinon'
import { expect } from 'chai'
import config from '../../src/config/config.js'
import { hasValidBasicAuth } from '../../src/utils/authentication.js'
import { UNSIGNED_EVENT_CODES } from '../../src/utils/commons.js'

describe('Basic Auth for non-HMAC (Generic Pending) notifications', () => {
  const sandbox = sinon.createSandbox()
  const ctpProjectKey = 'ctpProjectKey1'

  const requestWith = (authorization) => ({
    headers: authorization ? { authorization } : {},
  })
  const basic = (username, password) =>
    `Basic ${Buffer.from(`${username}:${password}`).toString('base64')}`
  const stubCredential = (authentication) =>
    sandbox
      .stub(config, 'getCtpConfig')
      .returns({ projectKey: ctpProjectKey, authentication })

  afterEach(() => sandbox.restore())

  it('accepts a request with the correct credentials', () => {
    stubCredential({ scheme: 'basic', username: 'adyen', password: 's3cret' })
    expect(
      hasValidBasicAuth(requestWith(basic('adyen', 's3cret')), ctpProjectKey),
    ).to.equal(true)
  })

  it('rejects a wrong password', () => {
    stubCredential({ scheme: 'basic', username: 'adyen', password: 's3cret' })
    expect(
      hasValidBasicAuth(requestWith(basic('adyen', 'nope')), ctpProjectKey),
    ).to.equal(false)
  })

  it('rejects a wrong username', () => {
    stubCredential({ scheme: 'basic', username: 'adyen', password: 's3cret' })
    expect(
      hasValidBasicAuth(
        requestWith(basic('attacker', 's3cret')),
        ctpProjectKey,
      ),
    ).to.equal(false)
  })

  it('rejects a missing Authorization header', () => {
    stubCredential({ scheme: 'basic', username: 'adyen', password: 's3cret' })
    expect(hasValidBasicAuth(requestWith(undefined), ctpProjectKey)).to.equal(
      false,
    )
  })

  it('rejects a non-Basic scheme', () => {
    stubCredential({ scheme: 'basic', username: 'adyen', password: 's3cret' })
    expect(
      hasValidBasicAuth(requestWith('Bearer sometoken'), ctpProjectKey),
    ).to.equal(false)
  })

  it('handles passwords that contain a colon', () => {
    stubCredential({
      scheme: 'basic',
      username: 'adyen',
      password: 'pa:ss:word',
    })
    expect(
      hasValidBasicAuth(
        requestWith(basic('adyen', 'pa:ss:word')),
        ctpProjectKey,
      ),
    ).to.equal(true)
  })

  it('fails closed when no credentials are configured', () => {
    stubCredential(undefined)
    expect(
      hasValidBasicAuth(requestWith(basic('adyen', 's3cret')), ctpProjectKey),
    ).to.equal(false)
  })
})

describe('UNSIGNED_EVENT_CODES allowlist', () => {
  it('contains PENDING (Generic Pending webhook is not HMAC-signed by Adyen)', () => {
    expect(UNSIGNED_EVENT_CODES.has('PENDING')).to.equal(true)
  })

  it('excludes money/state-changing events so they always require HMAC', () => {
    expect(UNSIGNED_EVENT_CODES.has('AUTHORISATION')).to.equal(false)
    expect(UNSIGNED_EVENT_CODES.has('CAPTURE')).to.equal(false)
    expect(UNSIGNED_EVENT_CODES.has('REFUND')).to.equal(false)
  })
})
