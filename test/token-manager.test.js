import { test, describe } from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'

import { TokenManager, RefreshError } from '../src/token-manager.js'
import { isExpiring, expiryMs } from '../src/jwt.js'
import { startOAuthServer, makeJwt } from './mock-oauth-server.js'

describe('1. proactive refresh: decode exp, refresh a fixed margin before expiry', () => {
  test('a token well inside its lifetime is reused, not refreshed', async () => {
    const oauth = await startOAuthServer({ expiresInSec: 3600 })
    try {
      const tm = new TokenManager({
        tokenUrl: oauth.url, clientId: 'id', clientSecret: 'secret',
        accessToken: makeJwt({}, { expiresInSec: 3600 }),
        marginMs: 60_000
      })
      await tm.getAccessToken()
      await tm.getAccessToken()
      assert.equal(oauth.requests.length, 0, 'should not have called the token endpoint')
    } finally { await oauth.close() }
  })

  test('a token inside the margin is refreshed before the request goes out', async () => {
    const oauth = await startOAuthServer({ expiresInSec: 3600 })
    try {
      const tm = new TokenManager({
        tokenUrl: oauth.url, clientId: 'id', clientSecret: 'secret',
        // 30s of life left, 60s margin: due for refresh.
        accessToken: makeJwt({}, { expiresInSec: 30 }),
        marginMs: 60_000
      })
      const token = await tm.getAccessToken()
      assert.equal(oauth.requests.length, 1)
      assert.ok(expiryMs(token) - Date.now() > 60_000, 'new token should outlive the margin')
    } finally { await oauth.close() }
  })

  test('the margin is the boundary, and it is honoured exactly', () => {
    const token = makeJwt({}, { expiresInSec: 100 })
    const exp = expiryMs(token)
    // One ms before the margin opens: not yet.
    assert.equal(isExpiring(token, 60_000, exp - 60_001), false)
    // Exactly on it: yes.
    assert.equal(isExpiring(token, 60_000, exp - 60_000), true)
  })

  test('an already-expired token refreshes', async () => {
    const oauth = await startOAuthServer()
    try {
      const tm = new TokenManager({
        tokenUrl: oauth.url, clientId: 'id',
        accessToken: makeJwt({}, { expiresInSec: -500 }),
        marginMs: 0
      })
      await tm.getAccessToken()
      assert.equal(oauth.requests.length, 1)
    } finally { await oauth.close() }
  })

  test('an opaque token falls back to expires_in from the token endpoint', async () => {
    // Opaque tokens carry no exp, so proactive refresh would be impossible
    // if the endpoint's own expires_in were ignored.
    const oauth = await startOAuthServer({ tokenStyle: 'opaque', expiresInSec: 50 })
    try {
      const tm = new TokenManager({
        tokenUrl: oauth.url, clientId: 'id', marginMs: 60_000
      })
      await tm.getAccessToken()
      assert.equal(oauth.requests.length, 1)
      // 50s lifetime, 60s margin: already inside it, so the next call refreshes.
      assert.equal(tm.needsRefresh(), true)
      await tm.getAccessToken()
      assert.equal(oauth.requests.length, 2)
    } finally { await oauth.close() }
  })

  test('an opaque token with no expires_in is left alone rather than refreshed every time', async () => {
    const calls = []
    const tm = new TokenManager({
      tokenUrl: 'http://unused.invalid/token',
      accessToken: 'opaque-no-expiry',
      fetchImpl: async (...args) => {
        calls.push(args)
        return new Response(JSON.stringify({ access_token: 'x' }), { status: 200 })
      }
    })
    await tm.getAccessToken()
    await tm.getAccessToken()
    assert.equal(calls.length, 0, 'no expiry signal means no opinion, not "expired"')
  })

  test('concurrent callers share one refresh', async () => {
    const oauth = await startOAuthServer()
    try {
      const tm = new TokenManager({ tokenUrl: oauth.url, clientId: 'id' })
      await Promise.all([tm.getAccessToken(), tm.getAccessToken(), tm.getAccessToken()])
      assert.equal(oauth.requests.length, 1, 'three callers, one token request')
    } finally { await oauth.close() }
  })
})

describe('3. custom headers survive the refresh call', () => {
  test('User-Agent and X-Client-ID reach the token endpoint', async () => {
    const oauth = await startOAuthServer()
    try {
      const tm = new TokenManager({
        tokenUrl: oauth.url,
        clientId: 'id',
        headers: { 'User-Agent': 'acme-ci/2.1', 'X-Client-ID': 'team-platform' }
      })
      await tm.getAccessToken()

      const sent = oauth.requests[0].headers
      assert.equal(sent['user-agent'], 'acme-ci/2.1')
      assert.equal(sent['x-client-id'], 'team-platform')
    } finally { await oauth.close() }
  })

  test('the protocol headers still win over a caller trying to set them', async () => {
    const oauth = await startOAuthServer()
    try {
      const tm = new TokenManager({
        tokenUrl: oauth.url, clientId: 'id', credentials: 'basic', clientSecret: 's',
        headers: { 'Content-Type': 'application/json', Authorization: 'Bearer wrong' }
      })
      await tm.getAccessToken()

      const sent = oauth.requests[0].headers
      assert.equal(sent['content-type'], 'application/x-www-form-urlencoded',
        'the body is form-encoded, so the caller cannot relabel it')
      assert.ok(sent.authorization.startsWith('Basic '),
        'basic mode owns the Authorization header')
    } finally { await oauth.close() }
  })

  test('no custom headers is fine', async () => {
    const oauth = await startOAuthServer()
    try {
      const tm = new TokenManager({ tokenUrl: oauth.url, clientId: 'id' })
      await tm.getAccessToken()
      assert.equal(oauth.requests.length, 1)
    } finally { await oauth.close() }
  })
})

describe('4. credentials in the body, not only HTTP Basic', () => {
  test('body mode sends client_id and client_secret in the form', async () => {
    // A provider that accepts only body credentials.
    const oauth = await startOAuthServer({ requireBodyCredentials: true })
    try {
      const tm = new TokenManager({
        tokenUrl: oauth.url, clientId: 'my-client', clientSecret: 'my-secret',
        credentials: 'body'
      })
      await tm.getAccessToken()

      const req = oauth.requests[0]
      assert.equal(req.params.client_id, 'my-client')
      assert.equal(req.params.client_secret, 'my-secret')
      assert.equal(req.headers.authorization, undefined, 'no Basic header in body mode')
    } finally { await oauth.close() }
  })

  test('body mode is the default', async () => {
    const oauth = await startOAuthServer({ requireBodyCredentials: true })
    try {
      const tm = new TokenManager({ tokenUrl: oauth.url, clientId: 'c', clientSecret: 's' })
      await tm.getAccessToken()
      assert.equal(oauth.requests[0].params.client_id, 'c')
    } finally { await oauth.close() }
  })

  test('basic mode still works for providers that require it', async () => {
    const oauth = await startOAuthServer({ requireBasic: true })
    try {
      const tm = new TokenManager({
        tokenUrl: oauth.url, clientId: 'my-client', clientSecret: 'my-secret',
        credentials: 'basic'
      })
      await tm.getAccessToken()

      const req = oauth.requests[0]
      const decoded = Buffer.from(req.headers.authorization.slice(6), 'base64').toString()
      assert.equal(decoded, 'my-client:my-secret')
      assert.equal(req.params.client_secret, undefined, 'secret must not be duplicated into the body')
    } finally { await oauth.close() }
  })

  test('an unknown credentials mode is rejected at construction, not at request time', () => {
    assert.throws(
      () => new TokenManager({ tokenUrl: 'http://x.invalid', credentials: 'header' }),
      /credentials must be/
    )
  })
})

describe('5. tokens are never written to disk', () => {
  test('a full refresh cycle touches no fs write API', async () => {
    const oauth = await startOAuthServer()
    const writeApis = [
      'writeFile', 'writeFileSync', 'appendFile', 'appendFileSync',
      'open', 'openSync', 'createWriteStream', 'writeSync', 'write'
    ]
    const originals = {}
    const calls = []

    for (const name of writeApis) {
      if (typeof fs[name] !== 'function') { continue }
      originals[name] = fs[name]
      fs[name] = (...args) => {
        calls.push({ name, arg: String(args[0]).slice(0, 120) })
        return originals[name](...args)
      }
    }

    try {
      const tm = new TokenManager({
        tokenUrl: oauth.url, clientId: 'id', clientSecret: 'secret',
        refreshToken: 'rt-1'
      })
      await tm.getAccessToken()
      await tm.refresh()
      assert.ok(tm.accessToken, 'sanity: a token was actually obtained')
      assert.deepEqual(calls, [], `fs writes during refresh: ${JSON.stringify(calls)}`)
    } finally {
      for (const [name, fn] of Object.entries(originals)) { fs[name] = fn }
      await oauth.close()
    }
  })

  test('the token lives on the instance and dies with it', async () => {
    const oauth = await startOAuthServer()
    try {
      let tm = new TokenManager({ tokenUrl: oauth.url, clientId: 'id' })
      const token = await tm.getAccessToken()
      assert.equal(tm.accessToken, token)

      // A fresh instance starts with nothing. No module-level cache, no file.
      tm = new TokenManager({ tokenUrl: oauth.url, clientId: 'id' })
      assert.equal(tm.accessToken, null)
      assert.equal(tm.needsRefresh(), true)
    } finally { await oauth.close() }
  })
})

describe('refresh token rotation and failure handling', () => {
  test('a rotated refresh token replaces the old one', async () => {
    // Providers that rotate invalidate the previous token on use, so keeping
    // the original breaks the second refresh, an hour into a long run.
    const oauth = await startOAuthServer({
      rotateRefreshToken: true, expectedRefreshToken: 'rt-initial'
    })
    try {
      const tm = new TokenManager({
        tokenUrl: oauth.url, clientId: 'id', refreshToken: 'rt-initial'
      })
      await tm.refresh()
      const rotated = tm.refreshToken
      assert.notEqual(rotated, 'rt-initial', 'should have adopted the rotated token')

      // The server rejects the previous token, so this only succeeds if the
      // rotated one was actually used.
      await tm.refresh()

      assert.equal(oauth.requests.length, 2)
      assert.equal(oauth.requests[0].params.refresh_token, 'rt-initial')
      assert.equal(oauth.requests[1].params.refresh_token, rotated,
        'the second refresh must send the rotated token, not the original')
    } finally { await oauth.close() }
  })

  test('a rejected refresh raises RefreshError with the status', async () => {
    const oauth = await startOAuthServer({ expectedRefreshToken: 'correct' })
    try {
      const tm = new TokenManager({
        tokenUrl: oauth.url, clientId: 'id', refreshToken: 'wrong'
      })
      await assert.rejects(() => tm.refresh(), (err) => {
        assert.ok(err instanceof RefreshError)
        assert.equal(err.status, 400)
        return true
      })
    } finally { await oauth.close() }
  })

  test('a non-JSON token response is an error, not a silent empty token', async () => {
    const tm = new TokenManager({
      tokenUrl: 'http://unused.invalid/token',
      fetchImpl: async () => new Response('<html>gateway error</html>', { status: 200 })
    })
    await assert.rejects(() => tm.refresh(), /did not return JSON/)
  })

  test('a 200 with no access_token is an error', async () => {
    const tm = new TokenManager({
      tokenUrl: 'http://unused.invalid/token',
      fetchImpl: async () => new Response(JSON.stringify({ token_type: 'Bearer' }), { status: 200 })
    })
    await assert.rejects(() => tm.refresh(), /no access_token/)
  })

  test('a failed refresh clears the in-flight guard so the next attempt is not stuck', async () => {
    let calls = 0
    const tm = new TokenManager({
      tokenUrl: 'http://unused.invalid/token',
      fetchImpl: async () => {
        calls++
        return new Response('nope', { status: 500 })
      }
    })
    await assert.rejects(() => tm.refresh())
    await assert.rejects(() => tm.refresh())
    assert.equal(calls, 2, 'second attempt must actually go out')
  })

  test('tokenUrl is required', () => {
    assert.throws(() => new TokenManager({}), /tokenUrl is required/)
  })
})
