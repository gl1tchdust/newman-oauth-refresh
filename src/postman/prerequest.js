/* eslint-disable */
/**
 * newman-oauth-refresh: collection pre-request module.
 *
 * Paste this into your collection's Pre-request Script tab, set the variables
 * listed below, and set each request's Authorization header to
 * `Bearer {{oauthAccessToken}}`.
 *
 * Why a pre-request script rather than a Newman event hook: Newman does not
 * await async event handlers, so a `beforeRequest` listener cannot refresh a
 * token before the request goes out. `pm.sendRequest` inside a pre-request
 * script *is* awaited, which makes this the only place a blocking refresh can
 * happen inside a Newman run.
 *
 * Required variables:
 *   oauthTokenUrl         token endpoint
 *
 * Optional variables:
 *   oauthClientId         client id
 *   oauthClientSecret     client secret
 *   oauthRefreshToken     enables grant_type=refresh_token
 *   oauthScope            scope string
 *   oauthCredentials      'body' (default) or 'basic'
 *   oauthMarginSec        refresh this many seconds before exp (default 60)
 *   oauthExtraHeaders     JSON object of headers to send on the refresh call
 *
 * Written for the Postman sandbox: ES5, no imports, no Buffer, no fs.
 */
(function () {
  var TOKEN_VAR = 'oauthAccessToken'
  var EXPIRY_VAR = 'oauthAccessTokenExpiresAt'

  function v (name, fallback) {
    var value = pm.variables.get(name)
    return (value === undefined || value === null || value === '') ? fallback : value
  }

  var tokenUrl = v('oauthTokenUrl', null)
  if (!tokenUrl) {
    throw new Error('newman-oauth-refresh: set the oauthTokenUrl variable')
  }

  var clientId = v('oauthClientId', null)
  var clientSecret = v('oauthClientSecret', null)
  var refreshToken = v('oauthRefreshToken', null)
  var scope = v('oauthScope', null)
  var credentials = v('oauthCredentials', 'body')
  var marginSec = Number(v('oauthMarginSec', 60))

  var extraHeaders = {}
  try {
    var rawHeaders = v('oauthExtraHeaders', null)
    if (rawHeaders) {
      extraHeaders = typeof rawHeaders === 'string' ? JSON.parse(rawHeaders) : rawHeaders
    }
  } catch (e) {
    throw new Error('newman-oauth-refresh: oauthExtraHeaders is not valid JSON')
  }

  // --- expiry ---------------------------------------------------------------
  //
  // Decoded, never verified. We are the client that was handed this token, not
  // the resource server that has to trust it.

  function b64urlDecode (input) {
    var s = String(input).replace(/-/g, '+').replace(/_/g, '/')
    while (s.length % 4 !== 0) { s += '=' }
    return atob(s)
  }

  function jwtExpiryMs (token) {
    if (typeof token !== 'string') { return null }
    var parts = token.split('.')
    if (parts.length !== 3) { return null }   // opaque token: no opinion
    try {
      var payload = JSON.parse(b64urlDecode(parts[1]))
      var exp = typeof payload.exp === 'string' ? Number(payload.exp) : payload.exp
      if (typeof exp !== 'number' || !isFinite(exp)) { return null }
      return exp * 1000
    } catch (e) {
      return null
    }
  }

  function needsRefresh () {
    var token = pm.variables.get(TOKEN_VAR)
    if (!token) { return true }

    var now = Date.now()
    var marginMs = marginSec * 1000

    // A JWT carries its own expiry.
    var exp = jwtExpiryMs(token)
    if (exp !== null) { return (exp - now) <= marginMs }

    // An opaque token does not, so fall back to what the token endpoint said
    // when it issued this one. Without either signal, do not refresh: the
    // 401 retry snippet in the README covers that case, and refreshing before
    // every request would defeat the point.
    var storedExpiry = Number(pm.variables.get(EXPIRY_VAR))
    if (storedExpiry) { return (storedExpiry - now) <= marginMs }

    return false
  }

  // --- refresh --------------------------------------------------------------

  function buildRequest () {
    var form = []
    var grantType = refreshToken ? 'refresh_token' : 'client_credentials'
    form.push('grant_type=' + encodeURIComponent(grantType))
    if (refreshToken) { form.push('refresh_token=' + encodeURIComponent(refreshToken)) }
    if (scope) { form.push('scope=' + encodeURIComponent(scope)) }

    // Caller headers first; the protocol bits below have to win. Everything
    // else the caller set is passed through, which is the point: dropping
    // User-Agent or a required X-Client-ID is how these refresh calls get
    // rejected by API gateways.
    var header = {}
    for (var k in extraHeaders) {
      if (Object.prototype.hasOwnProperty.call(extraHeaders, k)) {
        header[k] = extraHeaders[k]
      }
    }
    header['Content-Type'] = 'application/x-www-form-urlencoded'

    if (credentials === 'basic') {
      header.Authorization = 'Basic ' + btoa((clientId || '') + ':' + (clientSecret || ''))
    } else {
      // RFC 6749 2.3.1 allows credentials in the body, and some providers
      // accept nothing else. Forcing Basic breaks those outright.
      if (clientId) { form.push('client_id=' + encodeURIComponent(clientId)) }
      if (clientSecret) { form.push('client_secret=' + encodeURIComponent(clientSecret)) }
    }

    return {
      url: tokenUrl,
      method: 'POST',
      header: header,
      body: { mode: 'raw', raw: form.join('&') }
    }
  }

  if (!needsRefresh()) { return }

  pm.sendRequest(buildRequest(), function (err, res) {
    if (err) {
      throw new Error('newman-oauth-refresh: token request failed: ' + err)
    }
    if (res.code < 200 || res.code >= 300) {
      throw new Error('newman-oauth-refresh: token endpoint returned ' + res.code +
                      ': ' + String(res.text()).slice(0, 200))
    }

    var body = res.json()
    if (!body.access_token) {
      throw new Error('newman-oauth-refresh: token response has no access_token')
    }

    // pm.variables is run-scoped and in memory. Deliberately NOT
    // pm.environment.set with a persisted environment file: a token written
    // to disk outlives the run that needed it, on every CI runner it touches.
    pm.variables.set(TOKEN_VAR, body.access_token)

    if (typeof body.expires_in === 'number') {
      pm.variables.set(EXPIRY_VAR, String(Date.now() + body.expires_in * 1000))
    } else {
      pm.variables.set(EXPIRY_VAR, '')
    }

    // Rotation: a provider that issues a new refresh token invalidates the
    // old one, so keeping the original breaks the *second* refresh.
    if (body.refresh_token) {
      pm.variables.set('oauthRefreshToken', body.refresh_token)
    }
  })
})()
