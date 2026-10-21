/**
 * A fetch wrapper that attaches a bearer token and recovers from a 401 once.
 *
 * Two paths, because tokens come in two shapes:
 *
 *   Proactive  A JWT says when it expires, so refresh just before. The
 *              request never goes out with a token that dies in flight.
 *
 *   Reactive   An opaque token says nothing. The only way to learn it has
 *              expired is to be told, so take the 401, refresh, send the
 *              same request again, and carry on.
 *
 * Reactive alone is not enough: it turns every expiry into a visible failed
 * request, and some APIs rate-limit or alert on 401s. Proactive alone is not
 * enough either: it cannot work for opaque tokens, and clock skew between you
 * and the issuer will eventually beat any margin you pick. Both, or you have
 * a gap.
 */

/**
 * Exactly one retry. Not a loop.
 *
 * If the second 401 arrives, the token is not the problem: the credential is
 * wrong, the scope is missing, or the resource genuinely is not yours. Retrying
 * past that point turns an authorization bug into a self-inflicted flood
 * against the token endpoint, and hides the real error behind a timeout.
 */
const MAX_RETRIES = 1

/**
 * @param {import('./token-manager.js').TokenManager} tokenManager
 * @param {object} [options]
 * @param {Function} [options.fetchImpl]
 * @param {string}   [options.headerName]  default Authorization
 * @param {string}   [options.scheme]      default Bearer
 * @param {Function} [options.onRetry]     observability hook
 * @returns {(url: string, init?: object) => Promise<Response>}
 */
export function createAuthorizedFetch (tokenManager, options = {}) {
  const {
    fetchImpl = globalThis.fetch,
    headerName = 'Authorization',
    scheme = 'Bearer',
    onRetry = null
  } = options

  if (typeof fetchImpl !== 'function') {
    throw new TypeError('no fetch available; pass fetchImpl (Node 18+ has global fetch)')
  }

  return async function authorizedFetch (url, init = {}) {
    // Proactive. Refreshes only when the token is near expiry.
    let token = await tokenManager.getAccessToken()

    const send = (bearer) => fetchImpl(url, {
      ...init,
      headers: {
        // Caller headers first: a per-request header must not be lost just
        // because this wrapper has opinions about Authorization.
        ...(init.headers || {}),
        [headerName]: `${scheme} ${bearer}`
      }
    })

    let response = await send(token)

    for (let attempt = 0; attempt < MAX_RETRIES && response.status === 401; attempt++) {
      // Reactive. The server has told us the token is no good; believe it
      // rather than trusting our own expiry arithmetic.
      token = await tokenManager.refresh('reactive-401')
      if (onRetry) { onRetry({ url, attempt: attempt + 1 }) }
      response = await send(token)
    }

    return response
  }
}

/**
 * Is this request body safe to send a second time?
 *
 * A retry re-sends the body. Strings, buffers and URLSearchParams can be read
 * twice; a stream cannot, and the retry would go out with an empty body and
 * fail in a way that looks like a server bug. Callers sending streams should
 * buffer first, and this is here so they can check rather than find out.
 *
 * @param {*} body
 * @returns {boolean}
 */
export function isReplayable (body) {
  if (body === undefined || body === null) { return true }
  if (typeof body === 'string') { return true }
  if (body instanceof URLSearchParams) { return true }
  if (ArrayBuffer.isView(body) || body instanceof ArrayBuffer) { return true }
  // ReadableStream, Readable, FormData with a stream part: single use.
  return false
}
