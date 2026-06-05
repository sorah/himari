## [Unreleased]

### Enhancements

- Authorization Server Issuer Identification (RFC 9207): the authorization endpoint now returns the `iss` parameter in all authorization responses (success and redirected errors), and discovery metadata advertises `authorization_response_iss_parameter_supported`

## [0.6.0] - 2026-06-03

### Enhancements

- Refresh token (`refresh_token` grant) support [#14](https://github.com/sorah/himari/pull/14)
- Dynamic client registration (RFC 7591), Client ID Metadata Documents, an RFC 8414 `oauth-authorization-server` metadata endpoint, and Himari-owned `redirect_uri` matching with loopback-port relaxation and `Regexp` entries [#15](https://github.com/sorah/himari/pull/15)
- Interactive consent page gated by the client `skip_consent` attribute [#16](https://github.com/sorah/himari/pull/16)
- Per-client `scopes` allow-list [#17](https://github.com/sorah/himari/pull/17)
- Persist granted scopes on the grant and expose them to authorization rules as `context.scopes` [#19](https://github.com/sorah/himari/pull/19)
- Opt-in RFC 9068 (`at+jwt`) JWT access tokens [#20](https://github.com/sorah/himari/pull/20)
- Configurable `scopes_supported`/`claims_supported` and advertise `refresh_token`/`offline_access` in discovery metadata [#21](https://github.com/sorah/himari/pull/21)

## [0.5.0] - 2024-05-11

### Enhancements

- Userinfo endpoint now returns the `aud` claim.
- Client gains the `require_pkce` attribute.

## [0.4.0] - 2023-03-26

### Enhancements

- Support `prompt=login` for reauthentication; the userinfo endpoint now also answers POST [#8](https://github.com/sorah/himari/pull/8)
- Store `SessionData` in a storage backend [#7](https://github.com/sorah/himari/pull/7)
- Introduce the `omniauth-himari` strategy gem [#6](https://github.com/sorah/himari/pull/6)
- Access token gains its own lifetime.

### Changes

- Rename `AccessToken#handler` to `handle` and stop treating the token handle as a sensitive value [#5](https://github.com/sorah/himari/pull/5)
- Disable `Rack::Protection::JsonCsrf` for ALB OIDC compatibility [#1](https://github.com/sorah/himari/pull/1)

### Bug fixes

- Fix error when logging an expired session token.

## [0.3.0] - 2023-03-22

### Enhancements

- Customizable session and token lifetimes.
- `suggest=reauthenticate` to prompt login, with a decision `user_facing_message`.

### Bug fixes

- Callback returns 400 when the auth hash is missing.

## [0.2.0] - 2023-03-22

### Enhancements

- Better login page template with cachebuster.
- Prebuilt container image.

## [0.1.0] - 2023-02-25

- Initial release
