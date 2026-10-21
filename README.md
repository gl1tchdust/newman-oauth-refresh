# newman-oauth-refresh

[![ci](https://github.com/gl1tchdust/newman-oauth-refresh/actions/workflows/ci.yml/badge.svg)](https://github.com/gl1tchdust/newman-oauth-refresh/actions/workflows/ci.yml)

OAuth2 token refresh for [Newman](https://github.com/postmanlabs/newman) collection
runs. Proactive for JWTs, reactive on 401 for opaque tokens, and never writes a
token to disk.

## The problem

Postman's app refreshes OAuth2 tokens for you. Newman does not, so a collection
longer than the token's lifetime starts returning 401s partway through and
every request after that fails.

Two issues, and their states matter:

- [postmanlabs/postman-app-support#10112](https://github.com/postmanlabs/postman-app-support/issues/10112)
  "Auto update/refresh of OAuth2 access tokens" — **closed as completed**,
  March 2025. The app got it.
- [postmanlabs/newman#3219](https://github.com/postmanlabs/newman/issues/3219)
  "Automatic Token Refresh Not Working in Newman CLI When OAuth 2.0 Access
  Token Expires" — **still open.** The CLI did not.

So this is not a feature nobody got round to. It shipped in one product and
not the other, and Postman's documentation says so plainly: scheduled runs,
monitors, "the Postman CLI, and Newman don't support automatic token refresh"
([Postman docs, OAuth 2.0](https://learning.postman.com/docs/sending-requests/authorization/oauth-20/)).

That claim is checked, not quoted on trust. `scripts/premise.mjs` runs a
collection with Postman's own OAuth 2.0 auth block fully configured, refresh
token included, and expires the access token after the first request:

```
newman, unassisted: req/first:200  req/second:401  req/third:401
token endpoint calls: 0
```

Zero. Newman never attempted a refresh. CI runs that check on every push, and
**fails if Newman ever starts refreshing on its own** — at which point this
package should be retired rather than maintained.

## Three failure modes in the existing workarounds

Most published workarounds are a pre-request snippet that fetches a token
before every request. They mostly work, and they fail in three specific ways.

**1. The refresh call drops your custom headers.** Snippets build their token
request from scratch and send nothing but `Content-Type`. If your token
endpoint sits behind a gateway that requires a `User-Agent`, or your provider
wants an `X-Client-ID`, the refresh is rejected and the error you see is a
confusing 400 from an endpoint that worked yesterday. Headers you configure
here are passed through to the token call, and there is a test asserting they
arrive.

**2. They force HTTP Basic for client credentials.** RFC 6749 §2.3.1 permits
credentials in the request body, and a number of providers accept only that
form. A snippet hardcoded to `Authorization: Basic` cannot talk to them at all.
Body is the default here; Basic is one variable away.

**3. They cache the token to disk.** Usually by writing it into an environment
file so the next run can reuse it. That leaves a live bearer token on every CI
runner, in every container layer, and in anything that archives the workspace.
Nothing in this package reads or writes a token file, and a test monkeypatches
every `fs` write API to prove a full refresh cycle touches none of them.

A fourth, less often noticed: providers that **rotate** refresh tokens
invalidate the old one on use. Keeping the original breaks the *second*
refresh, an hour into a long run, which is a miserable thing to debug. Rotated
tokens are adopted automatically.

## 60-second quickstart

```bash
npm install newman-oauth-refresh
```

Running Newman as a library:

```js
import newman from 'newman'
import { withOAuthRefresh } from 'newman-oauth-refresh'

newman.run({
  collection: withOAuthRefresh(require('./collection.json')),
  envVar: [
    { key: 'oauthTokenUrl',     value: 'https://id.example.com/oauth2/token' },
    { key: 'oauthClientId',     value: process.env.CLIENT_ID },
    { key: 'oauthClientSecret', value: process.env.CLIENT_SECRET },
    { key: 'oauthRefreshToken', value: process.env.REFRESH_TOKEN }
  ]
}, (err, summary) => { /* ... */ })
```

Point your requests at `Bearer {{oauthAccessToken}}` and that is the whole
integration.

Prefer the CLI? Paste the module into your collection's **Pre-request Script**
tab once:

```bash
node -e "console.log(require('newman-oauth-refresh').preRequestScript())" > prerequest.js
```

then run `newman run collection.json` as usual.

## How it refreshes

Two paths, because tokens come in two shapes and neither path covers both.

**Proactive**, for JWTs. The token says when it expires, so decode `exp` and
refresh a fixed margin before. No request ever goes out carrying a token that
dies in flight, which is the thing that makes expiry bugs intermittent.
Signature verification is deliberately absent: we are the client that was
handed this token, not the resource server that has to trust it.

**Reactive**, for opaque tokens. Nothing in the token says anything, so the
401 is the only available signal. Take it, refresh, replay the request once,
carry on.

Reactive alone is not enough: it turns every expiry into a visible failed
request, and some gateways alert on 401 rates. Proactive alone is not enough
either: it cannot work for opaque tokens, and clock skew between you and the
issuer will eventually beat any margin you pick. Both, or there is a gap.

Exactly one retry, never a loop. A second 401 means the credential is wrong,
the scope is missing, or the resource genuinely is not yours, and retrying past
that turns an authorization bug into a flood against your token endpoint.

## What Newman actually allows

Four behaviours, each established by running real Newman rather than reading
about it. They shaped the design, and they are the reason this is a
pre-request module rather than an event hook.

| Behaviour | Result |
|---|---|
| Mutating headers in a `beforeRequest` listener | **works** |
| Newman awaiting an `async` event handler | **no** — the request goes out first |
| `pm.sendRequest` in a pre-request script being awaited | **yes** |
| `postman.setNextRequest` replaying the current request | **yes** |

The second row is the constraint everything else follows from. A
`beforeRequest` listener can stamp a header, but it cannot *wait* for a token,
so a Newman event hook can never refresh one. `pm.sendRequest` inside a
pre-request script is awaited, which makes the sandbox the only place a
blocking refresh can happen during a run. Hence a pre-request module.

The retry is the same story. Newman has no retry hook, so replaying a failed
request has to happen inside the sandbox, via `postman.setNextRequest`. The
generated snippet carries a guard variable: without one, a permanently
rejected token retries forever.

### A reporting quirk worth knowing

When a pre-request script issues its own `pm.sendRequest`, Newman reports the
item's execution **twice** in `summary.run.executions`. Both entries carry the
same `cursor.httpRequestId`, and the target server receives the request once.

Verified directly: a one-item collection produces two identical execution
entries while the mock API records a single request. If you assert on
execution counts in your own pipeline, deduplicate by `cursor.httpRequestId`
or you will chase a duplicate that was never sent. The tests here assert on
what the mock servers received instead.

## API

```js
import {
  TokenManager,          // the refresh logic, no Newman dependency
  createAuthorizedFetch, // fetch wrapper: proactive + reactive + one retry
  withOAuthRefresh,      // inject both scripts into a collection in memory
  preRequestScript,      // the module, as text
  retryOn401Script       // the retry snippet, as text
} from 'newman-oauth-refresh'
```

`TokenManager` and `createAuthorizedFetch` have no Newman dependency, so they
work in any Node code that needs a token kept fresh:

```js
const tokens = new TokenManager({
  tokenUrl: 'https://id.example.com/oauth2/token',
  clientId, clientSecret, refreshToken,
  credentials: 'body',                               // or 'basic'
  headers: { 'User-Agent': 'acme-ci/2.1' },          // sent on the refresh call
  marginMs: 60_000
})

const fetch = createAuthorizedFetch(tokens)
const res = await fetch('https://api.example.com/orders')
```

### Collection variables

| Variable | Default | Meaning |
|---|---|---|
| `oauthTokenUrl` | required | token endpoint |
| `oauthClientId` | | client id |
| `oauthClientSecret` | | client secret |
| `oauthRefreshToken` | | enables `grant_type=refresh_token` |
| `oauthScope` | | scope string |
| `oauthCredentials` | `body` | `body` or `basic` |
| `oauthMarginSec` | `60` | refresh this long before `exp` |
| `oauthExtraHeaders` | | JSON object of headers for the refresh call |

Set `oauthAccessToken` in your requests as `Bearer {{oauthAccessToken}}`.

## Limitations

- **A request body that is a stream cannot be retried.** The retry re-sends the
  body, and a stream is single use, so the replay would go out empty. Buffer
  first; `isReplayable(body)` tells you which case you are in.
- **No `authorization_code` flow.** This refreshes tokens, it does not perform
  an interactive grant. Obtain the first refresh token out of band.
- **Secrets come from you.** Pass them as environment variables. The package
  never persists one, but it cannot stop your CI logs from printing what you
  hand it.
- **The sandbox module is ES5.** Postman's sandbox is not Node, so the
  pre-request module avoids `Buffer`, imports and modern syntax deliberately.

## Tests

```bash
npm test          # 40 tests
npm run premise   # is the problem still real?
```

Every test runs against a real OAuth2 token endpoint and a real protected API
on real sockets, not a stubbed `fetch`. The three failure modes above are all
claims about what goes *on the wire* — which headers survive, where the
credentials are placed, whether an expired token is noticed — and a stub would
agree with any implementation, including a broken one.

The Newman tests drive actual Newman, for the same reason: this package's whole
premise is a claim about Newman's behaviour.

## License

MIT. See [LICENSE](LICENSE).

Shivam Mahajan, https://linkedin.com/in/shivam-mahajan-a8005a205
