# Refresh Tokens

Himari supports the OIDC `refresh_token` grant. When enabled, the token
endpoint returns a refresh token alongside the access token, and clients can
later exchange it for fresh tokens without sending the user back through the
upstream OmniAuth login.

The distinguishing feature in Himari is **revalidation on refresh**: every
refresh request re-runs your Claims, Authentication, and Authorization rules.
This lets you revoke access (group removed upstream, deny-list addition, etc.)
and have it take effect on the next refresh — not only when the session
finally expires.

## Enabling refresh tokens

Three things must line up. If any is missing, the token response simply omits
`refresh_token` and behavior is exactly as before.

1. **The client requests `offline_access`** in its OAuth `scope`.
2. **An AuthorizationRule (or client config) sets `lifetime.refresh_token`.**
   It defaults to `nil`, so refresh tokens are strictly opt-in.
3. **A rule marks the session refreshable** by setting `decision.refresh_info`
   (see below). Sessions without it return `invalid_grant` on refresh.

### Lifetime

Set the refresh token lifetime in an AuthorizationRule:

```ruby
use(Himari::Middlewares::AuthorizationRule, name: 'lifetime') do |context, decision|
  decision.lifetime = Himari::LifetimeValue.new(
    access_token: 3600,
    id_token: 3600,
    refresh_token: 86400 * 30, # 30 days
  )
  decision.allow!
end
```

`lifetime.refresh_token` is an **absolute cap** set at initial issuance. Rotation
preserves the token's original `expires_at` rather than sliding it forward, so a
rotation chain dies 30 days after sign-in regardless of how often it refreshes.
On each refresh the rules still re-evaluate `lifetime.refresh_token`, but it
gates only whether refresh is *still permitted* (omitting it rejects the
refresh) — it does not extend the chain.

## `refresh_info`: the revalidation snapshot

On a refresh request there is no OmniAuth callback — `context.auth` is `nil`.
So Himari cannot re-derive claims by re-reading the upstream auth hash. Instead,
your rule stores exactly the data it will need later into `decision.refresh_info`,
a free-form Hash persisted with the session.

`refresh_info` is the place for revalidation machinery — the upstream refresh
token, an access token, expiries, the upstream subject. Keep
application-facing identity (the provider name, profile fields) in
`decision.user_data` as before; the two have different lifecycles and different
audiences.

> **`refresh_info` is operator-controlled.** Whatever you put here is persisted
> with the session in your storage backend. Persist only what you need to
> re-verify the user — never blindly dump the whole OmniAuth auth hash, which
> typically contains upstream refresh tokens, id_tokens, and PII.

Setting `refresh_info` is what makes a session refreshable. It can be set from
either the Claims decision or the Authentication decision; if both set it, the
Authentication decision wins.

## Writing rules that handle refresh

Rules run on both the initial login and on refresh. Distinguish the two with
`context.initial?` / `context.refresh?` and structure each rule for a single
path using an early `decision.skip!`.

- `context.provider` is populated on **both** paths — from the auth hash on
  initial login, and from `session.user_data[:provider]` on refresh. For this
  to work on refresh, your initial rule must set
  `decision.user_data[:provider]`.
- `context.refresh_info` holds the snapshot your rule stored at sign-in.
- ClaimsRule may call `decision.deny!` to reject a refresh (e.g. the upstream
  provider says the user is gone). This produces `invalid_grant` with a typed
  reason in the logs, rather than relying on "no claims produced".

A GitHub example (full version in
[examples/config.github.ru](../examples/config.github.ru)):

```ruby
# Initial sign-in only: build claims, opt into refreshability.
use(Himari::Middlewares::ClaimsRule, name: 'github-initialize') do |context, decision|
  next decision.skip! unless context.initial?
  next decision.skip!("provider not in scope") unless context.provider == 'github'

  decision.initialize_claims!(
    sub: "github_#{context.auth[:uid]}",
    preferred_username: context.auth[:info][:nickname],
    email: context.auth[:info][:email],
  )
  decision.user_data[:provider] = 'github' # required for context.provider on refresh
  decision.refresh_info = {
    provider: 'github',
    sub: decision.claims[:sub],
    refresh_token: context.auth[:credentials][:refresh_token],
    access_token: context.auth[:credentials][:token],
  }
  decision.continue!
end

# Refresh only: exchange the upstream refresh token, rebuild claims,
# rotate the stored credentials.
use(Himari::Middlewares::ClaimsRule, name: 'github-revalidate') do |context, decision|
  next decision.skip! unless context.refresh?
  next decision.skip!("provider not in scope") unless context.refresh_info && context.refresh_info[:provider] == 'github'

  fresh = exchange_github_refresh_token(context.refresh_info[:refresh_token])
  next decision.deny!("upstream refused refresh") unless fresh

  decision.initialize_claims!(sub: context.refresh_info[:sub])
  decision.user_data[:provider] = 'github'
  decision.refresh_info = context.refresh_info.merge(
    refresh_token: fresh['refresh_token'] || context.refresh_info[:refresh_token],
    access_token: fresh['access_token'],
  )
  decision.continue!
end

# Both paths: gate on context.provider, read the current upstream access
# token from refresh_info (whichever rule above wrote it).
use(Himari::Middlewares::ClaimsRule, name: 'github-oauth-teams') do |context, decision|
  next decision.skip!("provider not in scope") unless context.provider == 'github'

  teams = fetch_github_teams(decision.refresh_info[:access_token])
  next decision.skip!("no teams in scope") if teams.empty?

  decision.claims[:groups] ||= []
  decision.claims[:groups].concat(teams)
  decision.continue!
end
```

> **Note on GitHub:** plain GitHub OAuth Apps do not issue refresh tokens. To
> obtain one you need a GitHub App with user-token expiration enabled. Providers
> vary — some don't rotate refresh tokens, some only return an id_token on the
> first exchange, some require an explicit `offline_access`-style scope.

## Client flow

Code exchange is unchanged except for the requested `scope`. When
`offline_access` was granted **and** `lifetime.refresh_token` is set, the
response includes a `refresh_token`:

```
POST /public/oidc/token
grant_type=authorization_code&code=...&redirect_uri=...
```

```json
{
  "token_type": "Bearer",
  "access_token": "hmat...",
  "id_token": "eyJ...",
  "refresh_token": "hmrt...",
  "expires_in": 3600
}
```

Refresh request:

```
POST /public/oidc/token
grant_type=refresh_token&refresh_token=hmrt...
```

```json
{
  "token_type": "Bearer",
  "access_token": "hmat...new...",
  "id_token": "eyJ...new...",
  "refresh_token": "hmrt...rotated...",
  "expires_in": 3600
}
```

- The `id_token` is returned on refresh only if the original grant was OIDC; it
  carries no `nonce`.
- The refresh token is **rotated in place**: its handle stays stable across
  refreshes, but each refresh mints a new secret (the `hmrt...` string changes)
  and returns it. The response always contains a fresh `refresh_token`.

## Rotation, secret window, and reuse handling

Rotation is done by updating one persistent token (stable handle) rather than
minting a new token and deleting the old one. This buys two properties:

- **Lost-response tolerance (window of 2).** The secret the client just
  presented stays valid as the *previous* secret for one more turn. If the
  rotation response is lost in transit, the client can retry with the secret it
  still holds and recover — no full re-auth. The previous secret is retired on
  the next successful rotation. A secret that is two generations old (matches
  neither current nor previous) is treated as a leak and revokes the token.
- **Conflict detection (compare-and-swap).** Each token carries a `version`
  counter (and an `updated_at` timestamp). A rotation writes conditionally on
  the version it read, so two refreshes that race against the same version are
  serialized: the winner's rotation stands, the loser gets `invalid_grant`
  **without** revoking the token. On DynamoDB this is an atomic conditional
  update; Memory/Filesystem use a (non-atomic) read-compare-write suited to
  their single-node use.

## Failure behavior

Most refresh-time failures return `invalid_grant` **and revoke the presented
refresh token** to neutralize replay. This is intentionally fail-closed:

- unknown / malformed / wrong-client refresh token
- a presented secret matching neither the current nor the previous secret
- session missing, expired, or not refreshable
- ClaimsRule `deny!`, AuthenticationRule `deny!`, or AuthorizationRule `deny!`

The **one** non-revoking failure is a version conflict (concurrent refresh): the
losing request returns `invalid_grant` but the token is left intact so the
winner's freshly rotated token survives.

## Security notes

- **You decide what is persisted.** `refresh_info` is operator-controlled —
  store the minimum needed to re-verify the user.
- **Rules run on every refresh.** If a rule calls an upstream API (e.g. to
  re-check group membership), it does so on each refresh. Consider caching or
  cheaper refresh-path logic via `context.refresh?` if upstream load is a
  concern.
- **Refresh tokens are bearer credentials**, stored hashed (`SHA384`) like
  access tokens. The previous secret is stored as a second hash; plaintext is
  never persisted.
- **Conflict detection is reject-the-loser, not family revocation.** A
  concurrent refresh fails for the loser but does not kill the token family, and
  within the two-secret window a replayed secret is tolerated rather than
  triggering revocation. There is also no `/revoke` endpoint — operators cannot
  proactively kill a refresh token without storage surgery.

See [examples/config.github.ru](../examples/config.github.ru) for a complete
working configuration, and [dev/config.ru](../dev/config.ru) /
[dev/config.rp.ru](../dev/config.rp.ru) for a local end-to-end rig.
