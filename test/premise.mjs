/**
 * Does the problem this package solves still exist?
 *
 * Run a collection configured with Postman's own OAuth 2.0 auth, including a
 * refresh token, and let the access token stop working partway through. If
 * Newman refreshes it on its own, this package is obsolete and should be
 * retired rather than quietly maintained.
 *
 * Postman's documentation states the limitation directly: "the Postman CLI,
 * and Newman don't support automatic token refresh". This script is the
 * executable form of that sentence, so the claim in the README is checked by
 * CI rather than trusted.
 *
 *   node test/premise.mjs
 *
 * Exit 0  the premise holds: unassisted Newman failed on the expired token
 * Exit 1  Newman refreshed on its own; this package is no longer needed
 */

import { createRequire } from 'node:module'
import { startOAuthServer, startProtectedApi } from './mock-oauth-server.js'

const require = createRequire(import.meta.url)
const newman = require('newman')

const SCHEMA = 'https://schema.getpostman.com/json/collection/v2.1.0/collection.json'

const oauth = await startOAuthServer({ tokenStyle: 'opaque' })

// The token is good for the first request and dead afterwards, which is the
// mid-run expiry from newman#3219.
let live = true
const api = await startProtectedApi({ acceptToken: (t) => live && t === 'initial-token' })

// Everything Postman's own OAuth 2.0 auth needs to refresh, handed to Newman
// on a plate. No pre-request module, no wrapper, nothing from this package.
const collection = {
  info: { name: 'premise', schema: SCHEMA },
  auth: {
    type: 'oauth2',
    oauth2: [
      { key: 'accessToken', value: 'initial-token', type: 'string' },
      { key: 'refreshToken', value: 'a-perfectly-good-refresh-token', type: 'string' },
      { key: 'accessTokenUrl', value: oauth.url, type: 'string' },
      { key: 'refreshTokenUrl', value: oauth.url, type: 'string' },
      { key: 'clientId', value: 'client', type: 'string' },
      { key: 'clientSecret', value: 'secret', type: 'string' },
      { key: 'grant_type', value: 'authorization_code', type: 'string' },
      { key: 'addTokenTo', value: 'header', type: 'string' },
      { key: 'tokenType', value: 'Bearer', type: 'string' }
    ]
  },
  item: ['/first', '/second', '/third'].map((p) => ({
    name: `req${p}`,
    request: { method: 'GET', url: `${api.url}${p}`, auth: null }
  }))
}

const summary = await new Promise((resolve, reject) => {
  const run = newman.run({ collection, reporters: [] }, (err, s) => {
    err ? reject(err) : resolve(s)
  })
  // Kill the token once the first request has been served.
  run.on('request', (err, args) => {
    if (!err && args.item.name === 'req/first') { live = false }
  })
})

const seen = new Set()
const results = summary.run.executions
  .filter((e) => {
    const id = e.cursor?.httpRequestId ?? e.item?.name
    if (seen.has(id)) { return false }
    seen.add(id)
    return true
  })
  .map((e) => `${e.item.name}:${e.response?.code}`)

console.log('newman, unassisted:', results.join('  '))
console.log('token endpoint calls:', oauth.requests.length)

const failedAfterExpiry = results.slice(1).some((r) => r.endsWith(':401'))

if (oauth.requests.length > 0) {
  console.error('\nNewman called the token endpoint by itself.')
  console.error('The premise has changed: retire this package rather than maintaining it.')
  process.exit(1)
}

if (!failedAfterExpiry) {
  console.error('\nEvery request succeeded despite the token being revoked mid-run.')
  console.error('Either Newman now refreshes tokens, or this check no longer tests anything.')
  process.exit(1)
}

console.log('\nPremise holds: Newman did not refresh, and the run failed after the token expired.')

await oauth.close()
await api.close()
