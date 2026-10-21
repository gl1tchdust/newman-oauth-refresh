/**
 * Read the expiry out of a JWT, without verifying it.
 *
 * Verification is deliberately absent. We are the client that was handed this
 * token, not the resource server that has to trust it. We do not have the
 * signing key and could not check it if we wanted to. The only question here
 * is "roughly when does the issuer say this stops working", so the right
 * amount of cryptography is none.
 *
 * Treating `exp` as advisory is also why a bad signature is not an error
 * worth throwing on: if the token is junk, the API will say so, and the
 * reactive 401 path handles it.
 */

/**
 * Decode a JWT payload. Returns null for anything that is not a JWT, which
 * includes every opaque token, and that is the normal case rather than an
 * error. Opaque tokens are handled reactively instead.
 *
 * @param {string} token
 * @returns {object|null}
 */
export function decodePayload (token) {
  if (typeof token !== 'string') { return null }

  const parts = token.split('.')
  if (parts.length !== 3) { return null }

  try {
    // base64url, and Buffer tolerates the missing padding.
    const json = Buffer.from(parts[1], 'base64url').toString('utf8')
    const payload = JSON.parse(json)
    // A JWT payload is a JSON object. An array or a bare number is not one,
    // and would make `payload.exp` silently undefined further down.
    return (payload && typeof payload === 'object' && !Array.isArray(payload))
      ? payload
      : null
  } catch {
    return null
  }
}

/**
 * Expiry as epoch milliseconds, or null when the token does not carry one.
 *
 * Null means "no opinion", not "expired". An opaque token has no expiry we
 * can read, and treating that as expired would refresh before every single
 * request.
 *
 * @param {string} token
 * @returns {number|null}
 */
export function expiryMs (token) {
  const payload = decodePayload(token)
  if (!payload) { return null }

  const { exp } = payload
  // RFC 7519 says exp is NumericDate, seconds since epoch. Some issuers send
  // it as a string. Accept both; reject anything else rather than producing
  // NaN, which compares false against everything and would disable refresh
  // without any visible failure.
  const seconds = typeof exp === 'string' ? Number(exp) : exp
  if (typeof seconds !== 'number' || !Number.isFinite(seconds)) { return null }

  return seconds * 1000
}

/**
 * Is this token within `marginMs` of expiring?
 *
 * False for tokens with no readable expiry. The caller decides what to do
 * with those; this function will not guess.
 *
 * @param {string} token
 * @param {number} marginMs how long before expiry to start saying yes
 * @param {number} [now] epoch ms, injectable so tests do not sleep
 * @returns {boolean}
 */
export function isExpiring (token, marginMs, now = Date.now()) {
  const expires = expiryMs(token)
  if (expires === null) { return false }
  return expires - now <= marginMs
}
