# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.1.1] - 2026-05-19

### Fixed

- IdP-initiated SSO flow no longer rejects all valid Responses with `:access_denied`. `validate_authresp/4` returned the bare atom `:ok` on the IdP-initiated success branch while the caller pattern-matched `{:ok, nonce}` inside `with`, making the whole success path dead code whenever `allow_idp_initiated_flow: true`. The function now returns `{:ok, flow, nonce}` (with `flow` ∈ `{:idp_initiated, :sp_initiated}` and `nonce: nil` for IdP-initiated), and `consume_signin_response/2` exposes a new `flow:` field in its success map so consumers no longer have to deduce the flow type from `nonce == nil` (#27, closes #24)
- `ExSaml.SPHandler.send_saml_response/3` no longer crashes with `Plug.Conn.AlreadySentError` (or a `nil` URL `ArgumentError`) when authentication fails and the target URL cannot be resolved. The error path now renders an HTML 403 response instead of attempting a redirect to a missing location (#26)

### Changed

- `consume_signin_response/2` success map now includes a `flow:` field (`:sp_initiated` or `:idp_initiated`). Additive — existing keys are unchanged (#27)
- Error atom `:idp_first_flow_not_allowed` renamed to `:idp_initiated_not_allowed` to align with standard SAML terminology used elsewhere in the module. In practice the previous atom was unobservable because the IdP-initiated flow itself was broken (#27)
- Internal `stale_time/1` rewritten in idiomatic Elixir — drops the verbatim-from-esaml nested-`case` structure with variable shadowing in favor of an `Enum.min/1` over collected candidate expiries. Same contract, with dedicated unit tests covering all three branches (#28, #14)

## [1.1.0] - 2026-05-06

### Added

- `ExSaml.Metadata.validate/1,2` and `ExSaml.Metadata.ValidationResult` for structural / SAML 2.0 spec-conformance validation of SP and IdP metadata (#20)

### Fixed

- SAMLResponse parsing no longer crashes with `{:wfc_Legal_Character, {:bad_character, _}}` on assertions containing non-ASCII characters (e.g. accented names). `xmerl_scan` was being fed pre-decoded Unicode codepoints via `to_charlist/1`; it now receives raw UTF-8 bytes via `:binary.bin_to_list/1` (#22)
- SP metadata generator no longer emits an `AssertionConsumerService` with the `HTTP-Redirect` binding, which violated SAML 2.0 Bindings §3.4.3 and Profiles §4.1.3.5 (#19)

### Documentation

- Drop ExDoc autolink to the hidden `ExSaml.Core.TableOwner` module in `start_ets/0`'s docstring (#23)

## [1.0.2] - 2026-04-16

### Security

- Fix XXE vulnerability ([CVE-2026-28809](https://cna.erlef.org/cves/CVE-2026-28809.html)) — add `allow_entities: false` to all `xmerl_scan.string` calls
- Add `NotBefore` time validation on assertions with 5-second clock skew tolerance
- Add algorithm whitelist — unknown signature algorithms now return `{:error, :unsupported_algorithm}` instead of crashing

## [1.0.1] - 2026-04-09

### Changed

- Fork `esaml` Erlang dependency into the project to remove unmaintained external dependency

### Fixed

- Audit issues from security review (#7)

## [1.0.0] - 2026-03-20

### Added

- Initial release as ExSaml, successor to [Samly](https://hex.pm/packages/samly)
- SP-initiated and IdP-initiated SSO flows
- Single Logout (SLO) support
- SP metadata generation
- Multi-IdP support with per-IdP configuration
- Pluggable assertion storage (ETS, Session, Nebulex cache)
- Relay state cache with anti-replay protection (`RelayStateCache.take/1`)
- Security headers plug (CSP with nonce, X-Frame-Options)
- Cryptographic nonce validation during auth flow
- Configurable cache backend via `config.exs`
- RSA-SHA1 signature rejection with `{:error, :insecure_algorithm}`
- Migration guide from Samly
- Module documentation across all public modules

### Removed

- Unused routes and pre-session create pipeline from Samly
- Hardcoded Nebulex cache — replaced with delegate pattern

[1.1.0]: https://github.com/docJerem/ex_saml/compare/v1.0.2...v1.1.0
[1.0.2]: https://github.com/docJerem/ex_saml/compare/v1.0.1...v1.0.2
[1.0.1]: https://github.com/docJerem/ex_saml/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/docJerem/ex_saml/releases/tag/v1.0.0
