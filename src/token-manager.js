import { isExpiring } from './jwt.js'

/**
 * Thrown when the token endpoint refuses to issue a token.
 *
 * Separate from a failure of the request you were actually trying to make,
 * because the two need different responses: a 401 from your API means refresh
 * and retry, a 401 from the token endpoint means your client credentials are
 * wrong and retrying will never help.
 */
export class RefreshError extends Error {
  constructor (message, { status, body } = {}) {
    super(message)
    this.name = 'RefreshError'
    this.status = status
    this.body = body
  }
}

const DEFAULT_MARGIN_MS = 60_000

/**
 * Holds an OAuth2 access token and refreshes it.
 *
 * Memory only. Nothing here reads or writes a file, and there is a test that
 * fails if that changes. A CLI that caches tokens on disk turns every CI
 * runner, every laptop, and every container layer into a place a bearer token
 * can be found later. The run is short; keeping the token in the process that
 * needs it costs nothing.
 */
export class TokenManager {
  /**
   * @param {object} options
   * @param {string} options.tokenUrl                 token endpoint
   * @param {string} [options.clientId]
   * @param {string} [options.clientSecret]
   * @param {string} [options.refreshToken]           for grant_type=refresh_token
   * @param {string} [options.accessToken]            a token you already hold
   * @param {string} [options.scope]
   * @param {'body'|'basic'} [options.credentials]    where client creds go
   * @param {object} [options.headers]                extra headers for the refresh call
   * @param {number} [options.marginMs]               refresh this long before exp
   * @param {'refresh_token'|'client_credentials'} [options.grantType]
   * @param {Function} [options.fetchImpl]            injectable for tests
   * @param {Function} [options.now]                  injectable clock
   * @param {Function} [options.onRefresh]            observability hook
   */
  constructor (options = {}) {
    const {
      tokenUrl,
      clientId,
      clientSecret,
      refreshToken,
      accessToken = null,
      scope,
      credentials = 'body',
      headers = {},
      marginMs = DEFAULT_MARGIN_MS,
      grantType = refreshToken ? 'refresh_token' : 'client_credentials',
      fetchImpl = globalThis.fetch,
      now = () => Date.now(),
      onRefresh = null
    } = options

    if (!tokenUrl) { throw new TypeError('tokenUrl is required') }
    if (credentials !== 'body' && credentials !== 'basic') {
      throw new TypeError(`credentials must be 'body' or 'basic', got ${credentials}`)
    }
    if (typeof fetchImpl !== 'function') {
      throw new TypeError('no fetch available; pass fetchImpl (Node 18+ has global fetch)')
    }

    this.tokenUrl = tokenUrl
    this.clientId = clientId
    this.clientSecret = clientSecret
    this.scope = scope
    this.credentials = credentials
    this.headers = headers
    this.marginMs = marginMs
    this.grantType = grantType
    this.onRefresh = onRefresh

    this._fetch = fetchImpl
    this._now = now

    // The only places a token lives. No disk, no module-level cache that
    // outlives the instance.
    this._accessToken = accessToken
    this._refreshToken = refreshToken
    // Set when the endpoint tells us expires_in but the token is opaque, so
    // even opaque tokens get proactive refresh when the server is helpful.
    this._expiresAtMs = null
    // Single-flight guard. A collection run fires requests back to back; if
    // three of them notice an expiring token at once, one refresh should go
    // out, not three. Concurrent refreshes also race to store the rotated
    // refresh token, and the loser's copy is already invalid.
    this._inFlight = null
  }

  /** The token currently held, without triggering a refresh. */
  get accessToken () { return this._accessToken }

  /** The refresh token currently held. Rotated values are kept up to date. */
  get refreshToken () { return this._refreshToken }

  /**
   * Should we refresh before using this token?
   *
   * Two independent signals, because tokens come in two shapes. A JWT carries
   * its own `exp` and we read it. An opaque token carries nothing, but the
   * token endpoint usually returned `expires_in`, so we remember that.
   * Neither available means no opinion, and the reactive 401 path covers it.
   */
  needsRefresh () {
    if (!this._accessToken) { return true }

    const now = this._now()
    if (isExpiring(this._accessToken, this.marginMs, now)) { return true }
    if (this._expiresAtMs !== null && this._expiresAtMs - now <= this.marginMs) {
      return true
    }
    return false
  }

  /**
   * A usable access token, refreshing first if it is close to expiry.
   *
   * This is the proactive path. For a JWT it means a request is never sent
   * with a token that is about to die mid-flight, which is the failure that
   * makes expiry bugs intermittent and miserable to reproduce.
   */
  async getAccessToken () {
    if (this.needsRefresh()) { await this.refresh('proactive') }
    return this._accessToken
  }

  /**
   * Refresh now, regardless of expiry. Used by the reactive 401 path.
   *
   * Concurrent callers share one in-flight request rather than stampeding
   * the token endpoint.
   *
   * @param {string} [reason] recorded for the onRefresh hook
   */
  async refresh (reason = 'forced') {
    if (this._inFlight) { return this._inFlight }

    this._inFlight = this._performRefresh(reason)
      .finally(() => { this._inFlight = null })
    return this._inFlight
  }

  async _performRefresh (reason) {
    const body = new URLSearchParams()
    body.set('grant_type', this.grantType)

    if (this.grantType === 'refresh_token') {
      if (!this._refreshToken) {
        throw new RefreshError('grant_type is refresh_token but no refresh token is held')
      }
      body.set('refresh_token', this._refreshToken)
    }
    if (this.scope) { body.set('scope', this.scope) }

    // Custom headers first, ours second. The protocol bits have to win:
    // the body encoding is ours to declare, and in basic mode the
    // Authorization header carries the client credentials. Everything else
    // the caller set is passed through untouched, which is the point.
    const headers = { ...this.headers }
    headers['Content-Type'] = 'application/x-www-form-urlencoded'

    if (this.credentials === 'basic') {
      const pair = `${this.clientId ?? ''}:${this.clientSecret ?? ''}`
      headers.Authorization = `Basic ${Buffer.from(pair).toString('base64')}`
    } else {
      // RFC 6749 §2.3.1 permits credentials in the body, and plenty of
      // providers accept only this form. Forcing Basic is a real-world
      // failure, not a style preference.
      if (this.clientId !== undefined) { body.set('client_id', this.clientId) }
      if (this.clientSecret !== undefined) { body.set('client_secret', this.clientSecret) }
    }

    const response = await this._fetch(this.tokenUrl, {
      method: 'POST',
      headers,
      body: body.toString()
    })

    const text = await response.text()
    if (!response.ok) {
      throw new RefreshError(
        `token endpoint returned ${response.status}`,
        { status: response.status, body: text.slice(0, 500) }
      )
    }

    let payload
    try {
      payload = JSON.parse(text)
    } catch {
      throw new RefreshError('token endpoint did not return JSON',
        { status: response.status, body: text.slice(0, 500) })
    }

    if (!payload.access_token) {
      throw new RefreshError('token response has no access_token',
        { status: response.status, body: text.slice(0, 500) })
    }

    this._accessToken = payload.access_token

    // Rotation. Providers that rotate refresh tokens invalidate the old one
    // on use, so keeping the original would break the *second* refresh and
    // look like an intermittent failure an hour into a long run.
    if (payload.refresh_token) { this._refreshToken = payload.refresh_token }

    this._expiresAtMs = typeof payload.expires_in === 'number'
      ? this._now() + payload.expires_in * 1000
      : null

    if (this.onRefresh) {
      this.onRefresh({
        reason,
        expiresIn: payload.expires_in ?? null,
        rotated: Boolean(payload.refresh_token)
      })
    }

    return this._accessToken
  }
}
