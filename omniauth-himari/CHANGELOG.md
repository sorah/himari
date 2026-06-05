## [0.4.0] - 2026-06-06

### Enhancements

- Validate the Authorization Server Issuer Identification `iss` parameter (RFC 9207) on the authorization response, defending against mix-up attacks; controlled by the new `verify_iss` option (default enabled)

## [0.3.0] - 2026-06-03

### Enhancements

- Add `scope` option (default `openid`) to request scopes from Himari [#14](https://github.com/sorah/himari/pull/14)

## [0.2.0] - 2023-03-26

### Enhancements

- Pass through the `prompt` parameter, supporting `prompt=login` reauthentication [#8](https://github.com/sorah/himari/pull/8)

## [0.1.1] - 2023-03-26

### Bug fixes

- Declare a direct dependency on the `jwt` gem.

## [0.1.0] - 2023-03-24

- Initial release
