import { test, describe } from 'node:test'
import assert from 'node:assert/strict'
import { createRequire } from 'node:module'
import vm from 'node:vm'

import { withOAuthRefresh, preRequestScript, retryOn401Script } from '../src/index.js'
import { startOAuthServer, startProtectedApi } from '../mocks/oauth-server.js'

const require = createRequire(import.meta.url)
const newman = require('newman')

/**
 * Run a collection and resolve with the summary.
 *
 * Real Newman against real sockets. The whole premise of this package is a
 * claim about Newman's behaviour, and a mocked Newman would agree with
 * whatever the implementation happened to do.
 */
function runCollection (collection, options = {}) {
  return new Promise((resolve, reject) => {
    newman.run({ collection, reporters: [], ...options }, (err, summary) => {
      if (err) { return reject(err) }
      resolve(summary)
    })
  })
}

/**
 * Compile without running. `new vm.Script` throws on a syntax error and never
 * executes the body, which is all a syntax check should do.
 */
function assertParses (source, label) {
  assert.doesNotThrow(() => new vm.Script(source), `${label} is not valid JavaScript`)
}

/**
 * Newman reports the same execution twice when a pre-request script issues
 * its own `pm.sendRequest`. Both entries carry the same `cursor.httpRequestId`
 * and the same `cursor.ref`, and the server receives the request only once,
 * so this is a reporting artifact rather than a duplicate call.
 *
 * Verified directly: a one-item collection with the pre-request module
 * produces two identical execution entries while the target API records a
 * single request. Tests assert on what the servers received wherever
 * possible; where an execution list is genuinely the right thing to inspect,
 * it gets deduplicated here first.
 */
function uniqueExecutions (summary) {
  const seen = new Set()
  return summary.run.executions.filter((e) => {
    const id = e.cursor?.httpRequestId ?? `${e.cursor?.ref}:${e.item?.name}`
    if (seen.has(id)) { return false }
    seen.add(id)
    return true
  })
}

const SCHEMA = 'https://schema.getpostman.com/json/collection/v2.1.0/collection.json'

function collectionFor (apiUrl, paths) {
  return {
    info: { name: 'oauth-refresh-test', schema: SCHEMA },
    item: paths.map((p) => ({
      name: `req-${p.replace('/', '')}`,
      request: {
        method: 'GET',
        url: `${apiUrl}${p}`,
        header: [{ key: 'Authorization', value: 'Bearer {{oauthAccessToken}}' }]
      }
    }))
  }
}

function vars (oauthUrl, extra = {}) {
  return Object.entries({
    oauthTokenUrl: oauthUrl,
    oauthClientId: 'test-client',
    oauthClientSecret: 'test-secret',
    oauthMarginSec: '60',
    ...extra
  }).map(([key, value]) => ({ key, value }))
}

describe('Newman end to end', () => {
  test('a collection run obtains a token and reuses it across requests', async () => {
    const oauth = await startOAuthServer({ tokenStyle: 'jwt', expiresInSec: 3600 })
    const api = await startProtectedApi({ acceptToken: (t) => t.split('.').length === 3 })
    try {
      const collection = withOAuthRefresh(collectionFor(api.url, ['/a', '/b', '/c']))
      const summary = await runCollection(collection, { envVar: vars(oauth.url) })

      const codes = uniqueExecutions(summary).map((e) => e.response?.code)
      assert.deepEqual(codes, [200, 200, 200])

      // Ground truth: what the target actually received, once each.
      assert.deepEqual(api.requests.map((r) => r.url), ['/a', '/b', '/c'])

      // One token, reused. A fresh token per request would mean the expiry
      // check is not working at all.
      assert.equal(oauth.requests.length, 1, 'should refresh once, not per request')
      const tokens = new Set(api.requests.map((r) => r.token))
      assert.equal(tokens.size, 1, 'all three requests carried the same token')
    } finally {
      await oauth.close()
      await api.close()
    }
  })

  test('custom headers reach the token endpoint from inside Newman', async () => {
    const oauth = await startOAuthServer()
    const api = await startProtectedApi({ acceptToken: () => true })
    try {
      const collection = withOAuthRefresh(collectionFor(api.url, ['/a']))
      await runCollection(collection, {
        envVar: vars(oauth.url, {
          oauthExtraHeaders: JSON.stringify({
            'User-Agent': 'acme-ci/2.1',
            'X-Client-ID': 'team-platform'
          })
        })
      })

      const sent = oauth.requests[0].headers
      assert.equal(sent['user-agent'], 'acme-ci/2.1')
      assert.equal(sent['x-client-id'], 'team-platform')
    } finally {
      await oauth.close()
      await api.close()
    }
  })

  test('credentials go in the body by default, and in Basic when asked', async () => {
    const bodyOauth = await startOAuthServer({ requireBodyCredentials: true })
    const basicOauth = await startOAuthServer({ requireBasic: true })
    const api = await startProtectedApi({ acceptToken: () => true })
    try {
      const collection = withOAuthRefresh(collectionFor(api.url, ['/a']))

      const bodyRun = await runCollection(collection, { envVar: vars(bodyOauth.url) })
      assert.equal(bodyRun.run.executions[0].response?.code, 200)
      assert.equal(bodyOauth.requests[0].params.client_id, 'test-client')

      const basicRun = await runCollection(collection, {
        envVar: vars(basicOauth.url, { oauthCredentials: 'basic' })
      })
      assert.equal(basicRun.run.executions[0].response?.code, 200)
      assert.ok(basicOauth.requests[0].headers.authorization.startsWith('Basic '))
    } finally {
      await bodyOauth.close()
      await basicOauth.close()
      await api.close()
    }
  })

  test('a token that stops working mid-run is retried once and the run resumes', async () => {
    // The scenario from newman#3219: the token dies partway through a
    // collection and every request after it fails.
    const oauth = await startOAuthServer({ tokenStyle: 'opaque', expiresInSec: 3600 })

    // Only the newest issued token is accepted, so a refresh heals the run
    // and a stale token does not.
    let killed = false
    const api = await startProtectedApi({
      acceptToken: (t) => t === `opaque-token-${oauth.issuedCount}` && !(killed && oauth.issuedCount === 1)
    })

    try {
      const collection = withOAuthRefresh(collectionFor(api.url, ['/a', '/b', '/c']))
      const run = newman.run({
        collection,
        reporters: [],
        envVar: vars(oauth.url, { oauthMarginSec: '0' })
      })

      // Expire the token immediately after the first request succeeds.
      run.on('request', (err, args) => {
        if (err) { return }
        if (args.item.name === 'req-a') { killed = true }
      })

      const summary = await new Promise((resolve, reject) => {
        run.on('done', (err, s) => err ? reject(err) : resolve(s))
      })

      const names = uniqueExecutions(summary).map((e) => `${e.item.name}:${e.response?.code}`)

      // req-b should have been served twice: a 401, then a 200 after refresh.
      const bAttempts = names.filter((n) => n.startsWith('req-b:'))
      assert.equal(bAttempts.length, 2, `expected one retry of req-b, got: ${names.join(' ')}`)
      assert.deepEqual(bAttempts, ['req-b:401', 'req-b:200'])

      // ...and the run carried on to the end rather than stopping there.
      assert.ok(names.includes('req-c:200'), `run did not resume: ${names.join(' ')}`)
      assert.equal(oauth.requests.length, 2, 'one initial token, one reactive refresh')
    } finally {
      await oauth.close()
      await api.close()
    }
  })
})

describe('script generation', () => {
  test('the pre-request module compiles', () => {
    const script = preRequestScript()
    assert.ok(script.includes('pm.sendRequest'))
    assertParses(script, 'pre-request module')
  })

  test('the retry snippet compiles and guards against looping', () => {
    const script = retryOn401Script()
    assertParses(script, 'retry snippet')
    assert.ok(script.includes('setNextRequest'))
    assert.ok(script.includes('oauthRetried'), 'must carry a loop guard')
  })

  test('the retry snippet can target a named request', () => {
    assert.ok(retryOn401Script({ itemName: 'Get Orders' }).includes('"Get Orders"'))
  })

  test('withOAuthRefresh does not mutate the collection it is given', () => {
    const original = collectionFor('http://x.invalid', ['/a'])
    const before = JSON.stringify(original)
    withOAuthRefresh(original)
    assert.equal(JSON.stringify(original), before)
  })

  test('withOAuthRefresh reaches requests nested in folders', () => {
    const collection = {
      info: { name: 'f', schema: SCHEMA },
      item: [{
        name: 'folder',
        item: [{ name: 'inner', request: { method: 'GET', url: 'http://x.invalid' } }]
      }]
    }
    const out = withOAuthRefresh(collection)
    const inner = out.item[0].item[0]
    assert.ok(inner.event.some((e) => e.listen === 'test'),
      'nested request should get the retry snippet')
  })

  test('retryOn401 can be turned off', () => {
    const out = withOAuthRefresh(collectionFor('http://x.invalid', ['/a']), { retryOn401: false })
    assert.equal(out.item[0].event, undefined)
    assert.ok(out.event.some((e) => e.listen === 'prerequest'), 'pre-request module still added')
  })
})
