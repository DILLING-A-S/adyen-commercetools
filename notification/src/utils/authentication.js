import { Buffer } from 'node:buffer'
import { timingSafeEqual } from 'node:crypto'
import config from '../config/config.js'

function getStoredCredential(ctpProjectKey) {
  const { authentication } = config.getCtpConfig(ctpProjectKey)
  if (authentication?.username && authentication?.password)
    return {
      username: authentication.username,
      password: authentication.password,
    }
  return null
}

// Constant-time comparison so a failed match does not leak how far it matched.
function safeEqual(a, b) {
  const bufferA = Buffer.from(String(a))
  const bufferB = Buffer.from(String(b))
  if (bufferA.length !== bufferB.length) return false
  return timingSafeEqual(bufferA, bufferB)
}

/*
 * Validates an HTTP Basic Auth header against the credentials stored for the given
 * commercetools project. Used to authenticate webhooks that Adyen does NOT HMAC-sign
 * (e.g. the Generic Pending webhook, eventCode PENDING), which can only be secured
 * with Basic Auth in the Adyen Customer Area.
 */
function hasValidBasicAuth(request, ctpProjectKey) {
  const storedCredential = getStoredCredential(ctpProjectKey)
  if (!storedCredential) return false

  const authorizationHeader = request?.headers?.authorization
  if (!authorizationHeader || !authorizationHeader.startsWith('Basic '))
    return false

  const decoded = Buffer.from(authorizationHeader.slice(6), 'base64').toString(
    'utf8',
  )
  // username cannot contain ":" per the Basic Auth spec, but the password can,
  // so split only on the first separator.
  const separatorIndex = decoded.indexOf(':')
  if (separatorIndex < 0) return false

  const username = decoded.slice(0, separatorIndex)
  const password = decoded.slice(separatorIndex + 1)

  // Evaluate both comparisons (no short-circuit) before combining the result.
  const usernameMatches = safeEqual(username, storedCredential.username)
  const passwordMatches = safeEqual(password, storedCredential.password)
  return usernameMatches && passwordMatches
}

export { hasValidBasicAuth }
