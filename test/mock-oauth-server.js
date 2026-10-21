/**
 * A mock OAuth2 token endpoint and a protected API, on real sockets.
 *
 * Deliberately a real HTTP server rather than a stubbed fetch. The three
 * failure modes this project exists to fix are all about what goes *on the
 * wire*: which headers survive, where the client credentials are placed, and
 * whether an expired token is noticed. A stub that returns a canned object
 * would agree with any implementation, including a broken one.
 *
 * Both servers record every request they receive so tests can assert on what
 * actually arrived rather than on what the code intended to send.
 */

import { createServer } from 'node:http'
import { Buffer } from 'node:buffer'

/** Build a JWT-shaped token. Unsigned: nothing here verifies signatures. */
export function makeJwt (claims = {}, { expiresInSec = 300 } = {}) {
  const enc = (obj) => Buffer.from(JSON.stringify(obj)).toString('base64url')
  const header = enc({ alg: 'none', typ: 'JWT' })
  const payload = enc({
    sub: 'test-subject',
    exp: Math.floor(Date.now() / 1000) + expiresInSec,
    ...claims
  })
  return `${header}.${payload}.${enc('unsigned-for-test')}`
}

function readBody (req) {
  return new Promise((resolve, reject) => {
    let data = ''
    req.on('data', (chunk) => { data += chunk })
    req.on('end', () => resolve(data))
    req.on('error', reject)
  })
}

/**
 * Start the token endpoint.
 *
 * @param {object} [options]
 * @param {'jwt'|'opaque'} [options.tokenStyle]
 * @param {number} [options.expiresInSec]  lifetime of each issued token
 * @param {boolean} [options.rotateRefreshToken]
 * @param {string}  [options.expectedRefreshToken] reject anything else
 * @param {boolean} [options.requireBasic] 401 unless creds arrive via Basic
 * @param {boolean} [options.requireBodyCredentials] 401 unless creds in body
 */
export async function startOAuthServer (options = {}) {
  const {
    tokenStyle = 'jwt',
    expiresInSec = 300,
    rotateRefreshToken = false,
    expectedRefreshToken = null,
    requireBasic = false,
    requireBodyCredentials = false
  } = options

  const requests = []
  let issued = 0
  let currentRefreshToken = expectedRefreshToken

  const server = createServer(async (req, res) => {
    const raw = await readBody(req)
    const params = new URLSearchParams(raw)
    const record = {
      method: req.method,
      url: req.url,
      headers: { ...req.headers },
      body: raw,
      params: Object.fromEntries(params)
    }
    requests.push(record)

    const json = (status, obj) => {
      res.writeHead(status, { 'Content-Type': 'application/json' })
      res.end(JSON.stringify(obj))
    }

    if (req.url !== '/token' || req.method !== 'POST') {
      return json(404, { error: 'not_found' })
    }

    const basic = (req.headers.authorization || '').startsWith('Basic ')
    if (requireBasic && !basic) {
      return json(401, { error: 'invalid_client', detail: 'Basic auth required' })
    }
    if (requireBodyCredentials && (basic || !params.get('client_id'))) {
      return json(401, { error: 'invalid_client', detail: 'credentials must be in the body' })
    }

    if (params.get('grant_type') === 'refresh_token') {
      const supplied = params.get('refresh_token')
      if (currentRefreshToken && supplied !== currentRefreshToken) {
        // What a rotating provider does to a client that reused an old token.
        return json(400, { error: 'invalid_grant', detail: 'refresh token not recognised' })
      }
    }

    issued += 1
    const accessToken = tokenStyle === 'jwt'
      ? makeJwt({ jti: `token-${issued}` }, { expiresInSec })
      : `opaque-token-${issued}`

    const payload = {
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: expiresInSec
    }

    if (rotateRefreshToken) {
      currentRefreshToken = `refresh-token-${issued + 1}`
      payload.refresh_token = currentRefreshToken
    }

    json(200, payload)
  })

  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
  const { port } = server.address()

  return {
    url: `http://127.0.0.1:${port}/token`,
    port,
    requests,
    get issuedCount () { return issued },
    get currentRefreshToken () { return currentRefreshToken },
    async close () { await new Promise((r) => server.close(r)) }
  }
}

/**
 * Start a protected API that only accepts tokens it has been told about.
 *
 * `acceptToken` is a predicate so a test can make a token stop working
 * mid-run, which is the whole situation being tested.
 */
export async function startProtectedApi ({ acceptToken } = {}) {
  const requests = []
  const accept = acceptToken || (() => true)

  const server = createServer(async (req, res) => {
    const auth = req.headers.authorization || ''
    const token = auth.startsWith('Bearer ') ? auth.slice(7) : null
    requests.push({ url: req.url, token, headers: { ...req.headers } })

    const json = (status, obj) => {
      res.writeHead(status, { 'Content-Type': 'application/json' })
      res.end(JSON.stringify(obj))
    }

    if (!token || !accept(token)) {
      return json(401, { error: 'invalid_token' })
    }
    json(200, { ok: true, sawToken: token })
  })

  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
  const { port } = server.address()

  return {
    url: `http://127.0.0.1:${port}`,
    port,
    requests,
    async close () { await new Promise((r) => server.close(r)) }
  }
}
