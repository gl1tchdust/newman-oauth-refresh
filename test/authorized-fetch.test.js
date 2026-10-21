import { test, describe } from 'node:test'
import assert from 'node:assert/strict'

import { TokenManager } from '../src/token-manager.js'
import { createAuthorizedFetch, isReplayable } from '../src/authorized-fetch.js'
import { startOAuthServer, startProtectedApi, makeJwt } from '../mocks/oauth-server.js'

describe('2. reactive refresh on 401, retry the failed request once, resume', () => {
  test('an opaque token that expires mid-run is recovered without the caller noticing', async () => {
    // Opaque tokens are the reason this path exists: nothing in the token
    // says when it dies, so the 401 is the only signal available.
    const oauth = await startOAuthServer({ tokenStyle: 'opaque' })

    // Only the most recently issued token is accepted. Issuing a new one
    // invalidates the last, which is what an expiry looks like from outside.
    let accepted = null
    const api = await startProtectedApi({ acceptToken: (t) => t === accepted })

    try {
      const tm = new TokenManager({
        tokenUrl: oauth.url,
        clientId: 'id',
        // No expires_in signal is used here: marginMs 0 keeps the proactive
        // path out of the way so the reactive path is what is under test.
        marginMs: 0,
        onRefresh: () => { accepted = `opaque-token-${oauth.issuedCount}` }
      })

      const retries = []
      const authFetch = createAuthorizedFetch(tm, { onRetry: (i) => retries.push(i) })

      // First call: no token yet, proactive refresh, succeeds.
      let res = await authFetch(`${api.url}/first`)
      assert.equal(res.status, 200)

      // The token silently stops working.
      accepted = 'something-else-entirely'

      res = await authFetch(`${api.url}/second`)
      assert.equal(res.status, 200, 'should have recovered via refresh and retry')
      assert.equal(retries.length, 1, 'exactly one retry')
      assert.equal(oauth.requests.length, 2, 'one initial token, one reactive refresh')

      // Resumed: the next request carries on with the new token, no retry.
      res = await authFetch(`${api.url}/third`)
      assert.equal(res.status, 200)
      assert.equal(retries.length, 1, 'no further retries once healthy')

      const paths = api.requests.map((r) => r.url)
      assert.deepEqual(paths, ['/first', '/second', '/second', '/third'],
        'the failed request is replayed, then the run continues')
    } finally {
      await oauth.close()
      await api.close()
    }
  })

  test('retries exactly once, never loops, when the 401 is not about expiry', async () => {
    // A token the API will never accept: wrong scope, wrong audience, or a
    // resource that simply is not yours. Retrying past once would hammer the
    // token endpoint and bury the real error.
    const oauth = await startOAuthServer({ tokenStyle: 'opaque' })
    const api = await startProtectedApi({ acceptToken: () => false })

    try {
      const tm = new TokenManager({ tokenUrl: oauth.url, clientId: 'id', marginMs: 0 })
      const authFetch = createAuthorizedFetch(tm)

      const res = await authFetch(`${api.url}/forbidden`)
      assert.equal(res.status, 401, 'the real error survives')
      assert.equal(api.requests.length, 2, 'original plus one retry, and no more')
      assert.equal(oauth.requests.length, 2, 'one initial token, one refresh attempt')
    } finally {
      await oauth.close()
      await api.close()
    }
  })

  test('a non-401 failure is returned untouched, with no refresh', async () => {
    const oauth = await startOAuthServer()
    const api = await startProtectedApi({ acceptToken: () => true })
    try {
      const tm = new TokenManager({
        tokenUrl: oauth.url, clientId: 'id',
        accessToken: makeJwt({}, { expiresInSec: 3600 })
      })
      const authFetch = createAuthorizedFetch(tm, {
        // 500s are not an authorization problem; refreshing would be noise.
        fetchImpl: async () => new Response('boom', { status: 500 })
      })
      const res = await authFetch(`${api.url}/x`)
      assert.equal(res.status, 500)
      assert.equal(oauth.requests.length, 0)
    } finally {
      await oauth.close()
      await api.close()
    }
  })

  test('caller headers survive the retry', async () => {
    const oauth = await startOAuthServer({ tokenStyle: 'opaque' })
    let accepted = null
    const api = await startProtectedApi({ acceptToken: (t) => t === accepted })
    try {
      const tm = new TokenManager({
        tokenUrl: oauth.url, clientId: 'id', marginMs: 0,
        onRefresh: () => { accepted = `opaque-token-${oauth.issuedCount}` }
      })
      const authFetch = createAuthorizedFetch(tm)

      await authFetch(`${api.url}/warm`)
      accepted = 'stale'
      await authFetch(`${api.url}/x`, { headers: { 'X-Request-Id': 'abc-123' } })

      const replay = api.requests.at(-1)
      assert.equal(replay.headers['x-request-id'], 'abc-123',
        'a per-request header must not be dropped by the retry')
    } finally {
      await oauth.close()
      await api.close()
    }
  })

  test('proactive and reactive compose: a JWT refreshes before it is ever rejected', async () => {
    const oauth = await startOAuthServer({ tokenStyle: 'jwt', expiresInSec: 3600 })
    const api = await startProtectedApi({ acceptToken: (t) => t.split('.').length === 3 })
    try {
      const tm = new TokenManager({
        tokenUrl: oauth.url, clientId: 'id',
        accessToken: makeJwt({}, { expiresInSec: 5 }),   // inside the margin
        marginMs: 60_000
      })
      const retries = []
      const authFetch = createAuthorizedFetch(tm, { onRetry: (i) => retries.push(i) })

      const res = await authFetch(`${api.url}/x`)
      assert.equal(res.status, 200)
      assert.equal(retries.length, 0, 'no 401 should ever have been seen')
      assert.equal(oauth.requests.length, 1, 'refreshed proactively, exactly once')
    } finally {
      await oauth.close()
      await api.close()
    }
  })
})

describe('replayability of request bodies', () => {
  test('bodies that can be sent twice are recognised', () => {
    assert.equal(isReplayable(undefined), true)
    assert.equal(isReplayable(null), true)
    assert.equal(isReplayable('{"a":1}'), true)
    assert.equal(isReplayable(new URLSearchParams({ a: '1' })), true)
    assert.equal(isReplayable(Buffer.from('x')), true)
    assert.equal(isReplayable(new ArrayBuffer(8)), true)
  })

  test('single-use bodies are flagged, because a retry would send an empty one', () => {
    const stream = new ReadableStream({ start (c) { c.enqueue('x'); c.close() } })
    assert.equal(isReplayable(stream), false)
  })
})

describe('construction', () => {
  test('a missing fetch is reported at setup, not on the first request', () => {
    const tm = new TokenManager({ tokenUrl: 'http://x.invalid', fetchImpl: async () => {} })
    assert.throws(() => createAuthorizedFetch(tm, { fetchImpl: null }), /no fetch available/)
  })
})
