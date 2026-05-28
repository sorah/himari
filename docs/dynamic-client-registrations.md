# Dynamic Client Registration (RFC 7591)

Himari can let clients register themselves at runtime via
[RFC 7591](https://www.rfc-editor.org/rfc/rfc7591) OAuth 2.0 Dynamic Client
Registration, instead of every client being declared statically with
`Himari::Middlewares::Client` in `config.ru`.

A client POSTs a JSON metadata document to the registration endpoint and
receives a freshly minted `client_id` (and, for confidential clients, a
one-time `client_secret`). The registration is persisted in the configured
storage backend and resolves through the same client lookup the OIDC
authorization and token endpoints already use.

> **No registration access token.** Himari implements registration only — there
> is no [RFC 7592](https://www.rfc-editor.org/rfc/rfc7592) configuration
> endpoint, so there is no read/update/delete of a registration, and no
> `registration_access_token` / `registration_client_uri` is issued. A
> registration is opaque after creation and simply expires (see
> [Lifetime](#lifetime)).

## Enabling

Add the middleware after `Himari::Middlewares::Config` (it reads `storage` from
the config):

```ruby
use(Himari::Middlewares::DynamicClients)
```

That single line:

1. Exposes the registration endpoint at **`POST /public/oidc/register`** (also
   reachable at `/oidc/register`). When the middleware is absent both routes
   return `404`.
2. Advertises `registration_endpoint` in the discovery documents
   (`/.well-known/openid-configuration` and
   `/.well-known/oauth-authorization-server`).
3. Appends a storage-backed client provider to the client chain, so registered
   `client_id`s resolve at authorize/token time.

### Options

```ruby
use(Himari::Middlewares::DynamicClients,
  registration_lifetime: 180 * 86400, # seconds a registration stays valid (default 180 days)
)
```

## Registering a client

```
POST /public/oidc/register
Content-Type: application/json

{
  "redirect_uris": ["https://app.example.net/auth/callback"],
  "client_name": "My App",
  "token_endpoint_auth_method": "client_secret_basic"
}
```

On success the endpoint returns `201 Created` with the RFC 7591 §3.2.1 client
information response:

```json
{
  "client_id": "g0K...24-byte-urlsafe...",
  "client_id_issued_at": 1748400000,
  "redirect_uris": ["https://app.example.net/auth/callback"],
  "grant_types": ["authorization_code"],
  "response_types": ["code"],
  "token_endpoint_auth_method": "client_secret_basic",
  "client_name": "My App",
  "client_secret": "one-time-secret-...",
  "client_secret_expires_at": 1763952000
}
```

The `client_secret` is generated server-side and **only ever returned in this
response** — only its SHA-384 hash is persisted, so it cannot be retrieved
later. Store it when you register.

### Supported metadata

| Field | Default | Notes |
| --- | --- | --- |
| `redirect_uris` | — | **Required**, non-empty array. Each must be an absolute URI with a scheme, no fragment, ≤ 2000 chars. Up to 32 entries. The schemes `javascript`, `data`, `vbscript`, `file`, `blob` are rejected. |
| `token_endpoint_auth_method` | `client_secret_basic` | One of `none`, `client_secret_basic`, `client_secret_post`. `none` makes the client public (no secret). |
| `grant_types` | `["authorization_code"]` | Subset of `authorization_code`, `refresh_token`. |
| `response_types` | `["code"]` | Only `code` is supported. Requesting `code` requires `authorization_code` in `grant_types`. |
| `client_name` | — | Optional, ≤ 60 chars. |
| `client_uri` | — | Optional; must be an absolute URI with scheme and host, ≤ 2000 chars. |
| `scope` | — | Optional, stored and echoed back. |

Unknown metadata fields are ignored.

### Confidential vs. public clients

- `token_endpoint_auth_method` other than `none` → **confidential**: a
  `client_secret` is issued and required at the token endpoint.
- `token_endpoint_auth_method: "none"` → **public**: no secret is issued, and
  **PKCE is mandatory** (the authorization code is otherwise unbound). Use this
  for SPAs, native, and CLI clients.

### Errors

Validation failures return `400` with an RFC 7591 §3.2.2 error body, e.g.:

```json
{ "error": "invalid_redirect_uri", "error_description": "redirect_uris is required and must be a non-empty array" }
```

The error codes used are `invalid_redirect_uri` and `invalid_client_metadata`.
A non-POST request returns `405`, and a body that is not a JSON object returns
`400 invalid_client_metadata`.

## Lifetime

Each registration carries an absolute expiry (`client_secret_expires_at`),
`registration_lifetime` seconds after issuance (default 180 days). After that
the client lookup treats it as unknown and the authorization/token endpoints
reject it. There is no renewal — the client must register again.

Expiry is enforced in two places so it holds regardless of backend: the storage
provider filters out expired registrations on lookup (so Memory and Filesystem,
which have no native TTL, still fail closed), and on DynamoDB the record also
carries a TTL attribute for eventual cleanup.

## How registered clients differ from static clients

Registered clients flow through the exact same `client_provider.find(id:)`
lookup as `Himari::Middlewares::Client`, but:

- They have **no friendly name**. AuthorizationRules that key on
  `context.client.name` will never match a dynamic client — design rules so the
  default path covers (or explicitly denies) anonymous clients if you enable
  registration on a sensitive deployment.
- The registration record retains the registrant's IP / `REMOTE_ADDR` /
  `X-Forwarded-For` for audit, but these are not exposed to rules.

## Security notes

- **Registration is unauthenticated.** Anyone who can reach
  `/public/oidc/register` can mint a client. This is acceptable because clients
  still cannot get tokens without passing your Authentication and Authorization
  rules, but you should ensure those rules do not implicitly trust "any client".
  Consider fronting the endpoint with network controls if open registration is
  not desired.
- **Secrets are write-once.** Only the SHA-384 hash is stored; a lost secret
  means re-registering.
- **`redirect_uris` are matched exactly** at authorize time, as with static
  clients.

See [dev/config.ru](../dev/config.ru) for a working local configuration.
