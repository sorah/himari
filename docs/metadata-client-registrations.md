# Client ID Metadata Document

Himari can accept a `client_id` that is itself an **https URL** pointing to a
JSON client metadata document, per the
[OAuth Client ID Metadata Document](https://datatracker.ietf.org/doc/draft-ietf-oauth-client-id-metadata-document/)
draft (`draft-ietf-oauth-client-id-metadata-document`). Instead of registering
ahead of time (see [Dynamic Client Registration](./dynamic-client-registrations.md)),
a client simply hosts its own metadata at a URL and uses that URL as its
`client_id`. Himari fetches and validates the document on demand.

This is well suited to decentralized clients that can publish a static document
but cannot pre-register — e.g. the pattern popularized by AT Protocol /
Bluesky.

## Enabling

Add the middleware after `Himari::Middlewares::Config`:

```ruby
use(Himari::Middlewares::MetadataClients)
```

That:

1. Registers a client provider that resolves URL `client_id`s by fetching their
   metadata document.
2. Advertises `client_id_metadata_document_supported: true` in the discovery
   documents.

There is no new endpoint — the URL `client_id` is consumed directly at the
authorization and token endpoints.

### Options

```ruby
use(Himari::Middlewares::MetadataClients,
  # Optional allowlist of acceptable client_id URLs. Empty (default) accepts any
  # compliant https URL. Entries are String (exact match) or Regexp (=~).
  allowed_client_ids: [%r{\Ahttps://[^/]+\.example\.com/}],

  # Force PKCE for these clients. Default true; they are always public.
  require_pkce: true,

  # SSRF filtering. true (default) restricts fetches to https and blocks
  # special-use IPs. A Hash is merged into the ssrf_filter plugin options.
  # false disables filtering — only for an authorization server on loopback.
  ssrf: true,

  # Fetch tuning.
  user_agent: 'Himari-OauthClientMetadataFetch/... (+https://github.com/sorah/himari)',
  http_timeout: { connect_timeout: 5, request_timeout: 10, read_timeout: 10 },
  max_response_size: 5120, # bytes; documents larger than this are rejected

  # Cache bounds (seconds). The document's Cache-Control/Expires is honored
  # within [cache_min_ttl, cache_max_ttl]; cache_default_ttl applies when the
  # response gives no usable directive.
  cache_min_ttl: 60,
  cache_max_ttl: 86400,
  cache_default_ttl: 300,

  # Approximate cap (bytes) on the total size of cached documents. When exceeded,
  # the oldest entries are evicted until the total fits. Default 1 MiB.
  cache_max_total_size: 1_048_576,
)
```

## How a client uses it

The client hosts a JSON document at a URL and uses that URL as its `client_id`:

```
GET https://app.example.com/oauth-client.json
Content-Type: application/json

{
  "client_id": "https://app.example.com/oauth-client.json",
  "client_name": "My App",
  "redirect_uris": ["https://app.example.com/auth/callback"],
  "token_endpoint_auth_method": "none"
}
```

Then it begins an ordinary authorization-code + PKCE flow with
`client_id=https://app.example.com/oauth-client.json`. Himari fetches the
document and treats the client as a public client.

## Validation rules

For a `client_id` to be accepted:

**As a URL** (checked before any fetch):

- Scheme must be `https`.
- No fragment, no userinfo (`user:pass@`).
- Must have a non-empty path with no `.` / `..` path segments.
- Must match `allowed_client_ids` if that option is set.

**The fetch** (the draft forbids following redirects):

- Only a `200` response is accepted — any 3xx/4xx/5xx is an error.
- `Content-Type` must be `application/json` (or `*+json`).
- Body must not exceed `max_response_size`. The response is **streamed** and the
  read is aborted as soon as the cap is exceeded (a `Content-Length` header over
  the cap is rejected up front), so a host that omits `Content-Length` cannot
  make Himari buffer an unbounded body.

**The document:**

- Must be a JSON object whose `client_id` **exactly equals** the request URL.
- Must **not** contain `client_secret` / `client_secret_expires_at` (these
  clients are always public).
- `token_endpoint_auth_method`, if present, must be `none`.
- `redirect_uris` is validated exactly as in
  [Dynamic Client Registration](./dynamic-client-registrations.md#supported-metadata)
  (absolute URIs, no fragment, length and scheme limits).

The client is always presented as **public**, so PKCE is required (unless you
explicitly set `require_pkce: false`).

## Failure behavior

The provider **fails closed**: any transport error, SSRF rejection, non-200
response, oversized body, wrong content type, malformed JSON, or failed
validation results in the `client_id` being treated as *unknown* (the
authorization endpoint returns "unknown client") rather than raising. Rejections
are logged with the reason.

## Caching

Successfully fetched and validated documents are cached in-memory by the
provider for connection-less reuse across requests. The TTL honors the
response's `Cache-Control: max-age` or `Expires`, clamped to
`[cache_min_ttl, cache_max_ttl]`; `no-store` / `no-cache` disables caching for
that document. Errors and malformed documents are never cached. The cache and
its HTTPX session live for the process lifetime, so they reset on redeploy.

The cache is bounded by `cache_max_total_size`: it tracks the approximate total
size of cached documents (by original JSON body bytes) and, once that budget is
exceeded, evicts the oldest entries until the total fits again.

## SSRF considerations

Because Himari fetches an attacker-influenced URL, SSRF filtering is **on by
default**: fetches are restricted to `https` and the `ssrf_filter` HTTPX plugin
blocks special-use / private IP ranges. Redirects are never followed.

- Tighten or extend it by passing a Hash (merged into the plugin options).
- Set `ssrf: false` **only** when running the authorization server on a
  loopback address for local testing, where the filter would otherwise block
  your own test target.
- Combine with `allowed_client_ids` to restrict which hosts may serve client
  metadata at all.

See [dev/config.ru](../dev/config.ru) for a commented configuration example.
