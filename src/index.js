import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

export { TokenManager, RefreshError } from './token-manager.js'
export { createAuthorizedFetch, isReplayable } from './authorized-fetch.js'
export { decodePayload, expiryMs, isExpiring } from './jwt.js'

const here = dirname(fileURLToPath(import.meta.url))

/**
 * The pre-request module, as text, ready to paste into a collection's
 * Pre-request Script tab or to inject programmatically.
 *
 * This is the only `readFileSync` in the package, and it reads this package's
 * own source. No token ever touches the filesystem; see the test that asserts
 * it.
 *
 * @returns {string}
 */
export function preRequestScript () {
  return readFileSync(join(here, 'postman', 'prerequest.js'), 'utf8')
}

/**
 * The test-script snippet that retries a request once after a 401.
 *
 * Newman has no retry hook, and it does not await async event handlers, so
 * neither a wrapper nor a `beforeRequest` listener can replay a failed
 * request. `postman.setNextRequest` can, because it runs inside the sandbox
 * where the collection's own control flow lives.
 *
 * The guard variable matters. Without it a permanently rejected token
 * retries forever, turning an authorization bug into an infinite loop
 * against the token endpoint.
 *
 * @param {object} [options]
 * @param {string} [options.itemName] the request's own name; defaults to the
 *   runtime value, which is correct unless the request is renamed mid-run
 * @returns {string}
 */
export function retryOn401Script (options = {}) {
  const target = options.itemName
    ? JSON.stringify(options.itemName)
    : 'pm.info.requestName'

  return [
    '// newman-oauth-refresh: retry once after a 401.',
    '// Pair with the pre-request module, which does the refreshing.',
    'if (pm.response.code === 401) {',
    "  var key = 'oauthRetried:' + pm.info.requestName;",
    '  if (!pm.variables.get(key)) {',
    "    pm.variables.set(key, '1');",
    "    pm.variables.set('oauthAccessToken', '');        // force a refresh",
    "    pm.variables.set('oauthAccessTokenExpiresAt', '');",
    `    postman.setNextRequest(${target});`,
    '  }',
    '} else {',
    "  pm.variables.unset('oauthRetried:' + pm.info.requestName);",
    '}'
  ].join('\n')
}

/**
 * Inject both scripts into a collection object in memory.
 *
 * Returns a new collection; the input is not modified. Useful when you run
 * Newman as a library and would rather not hand-edit the collection file,
 * which also keeps the scripts out of version control alongside your tests.
 *
 * @param {object} collection a Postman v2.1 collection
 * @param {object} [options]
 * @param {boolean} [options.retryOn401] also add the retry snippet to each item
 * @returns {object}
 */
export function withOAuthRefresh (collection, options = {}) {
  const { retryOn401 = true } = options
  const next = structuredClone(collection)

  next.event = (next.event || []).filter((e) => e.listen !== 'prerequest')
  next.event.push({
    listen: 'prerequest',
    script: { type: 'text/javascript', exec: preRequestScript().split('\n') }
  })

  if (retryOn401) {
    const snippet = retryOn401Script().split('\n')
    const addTo = (items) => {
      for (const item of items || []) {
        if (item.item) { addTo(item.item); continue }   // folder
        item.event = (item.event || []).filter((e) => e.listen !== 'test')
        item.event.push({
          listen: 'test',
          script: { type: 'text/javascript', exec: snippet }
        })
      }
    }
    addTo(next.item)
  }

  return next
}
