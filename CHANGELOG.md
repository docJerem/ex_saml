# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `error_id` callback contract, symmetric with the authorization `code`: when the assertion consumer service cannot complete a sign-in, `ExSaml.SPHandler` now stores an `%ExSaml.Error{}` in the new `ExSaml.ErrorCache` (single-use, 5 min TTL, `config :ex_saml, error_ttl:`) and redirects to `target_url?error_id=<id>`. Consumers redeem it with `ExSaml.Error.get_from_id/1`, exactly like `ExSaml.Assertion.get_from_code/1`, without depending on the browser session across the cross-site IdP POST. The struct carries `reason` (unchanged vocabulary), `step`, `flow`, `idp_id`, `relay_state`, `saml_status` / `saml_sub_status`, `node`, `at`, `debug_id` and `details` (#54)
- `ExSaml.Debug`: runtime debug mode stored in the configured Nebulex cache. `enable/1` (global or `idp_id:`, always with a TTL, default 1 h), `disable/1`, `status/0`, `enabled?/1`, `report/1`. Enabled from a remote console or `bin/app rpc` without a redeploy, restart or config change; visible to every node sharing the cache; auto-expiring; never breaks the auth flow when the cache fails. When on, every decision point of the flow is logged at `:warning` with its full context and appended to a per-flow report: AuthnRequest, ACS request (raw `SAMLResponse`, cookie names, session snapshot, relay-state cache hit), decoding, IdP status, validation with the provenance (session vs cache) of relay_state / idp_id / nonce, code issuance, code storage and redemption, error issuance, logout failures. Node-local fallback when no cache is configured; `config :ex_saml, debug: true` static override for dev/test (#54)
- `ExSaml.Core.StatusCode`: full catalogue of the 23 SAML 2.0 `StatusCode` URIs (4 top level, 19 second level) with `to_atom/1`, `to_uri/1`, `top_level?/1`, `second_level?/1`. `ExSaml.Core.Sp` now reads the nested second-level `StatusCode`, `StatusMessage` and `StatusDetail` of a non-success response; the public `{:saml_error, status, message}` tuple is unchanged and the nested code is exposed through `%ExSaml.Error{saml_sub_status: _}` and `ExSaml.ErrorMessages` (#54)
- English consumer guide `guides/error_handling_and_debugging.md`: callback contract, `%ExSaml.Error{}` reference and catalogue of reasons, legacy session behaviour, debug mode, troubleshooting recipes (#54)
- `ExSaml.ErrorMessages` (en/fr) now covers every reason produced on the sign-in path, every signature verification error and every second-level SAML status (#54)

### Changed

- `ExSaml.SPHandler.consume_signin_response/1` fails closed: an unknown `idp_id` yields `{:unknown_idp, idp_id}`, a missing `SAMLResponse` yields `:missing_saml_response`, and any exception raised while consuming the response is rescued, logged, and turned into an `error_id` redirect with reason `{:exception, message}` instead of a bare 500 (#54)
- `ExSaml.ErrorMessages.get/2` no longer raises on an unknown code: it returns the generic `unknown_error` message and logs the raw code at `:warning`. It also accepts `%ExSaml.Error{}` and resolves `{:saml_error, _, _}` through the status catalogue instead of an exact-match on `:undefined` messages that never matched (#54)
- Authorization code payload gains an additive `debug_id:` key (`nil` unless debug mode is on) (#54)
- `ExSaml.Assertion.get_from_code/1` logs a missing / expired code at `:warning` (was `:info`) with the code (#54)
- `ExSaml.Core.Saml` status mapping delegates to `ExSaml.Core.StatusCode`; historical atoms (`:bad_version`, `:bad_attr`, `:denied`, `:bad_binding`, `:authn_failed`) are preserved, and the 17 other spec statuses now map to their catalogue atom instead of a raw URI suffix (#54)

## [1.1.2] - 2026-06-08

### Fixed

- AuthnRequest generation no longer ignores a caller-supplied SAML nonce. `ExSaml.AuthHandler` now resolves the nonce via `conn.assigns[:saml_nonce]` first, falling back to the encrypted `saml_nonce` cookie and finally a fresh `UUID.uuid4/0`. Because `put_resp_cookie/4` does not populate `req_cookies`, the previous cookie-only lookup could not see a nonce the SP had just set on the same round-trip, so any auxiliary state (e.g. `redirect_uri`) persisted under that key failed to resolve when the IdP response came back (#36)

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

[1.1.2]: https://github.com/docJerem/ex_saml/compare/v1.1.1...v1.1.2
[1.1.1]: https://github.com/docJerem/ex_saml/compare/v1.1.0...v1.1.1
[1.1.0]: https://github.com/docJerem/ex_saml/compare/v1.0.2...v1.1.0
[1.0.2]: https://github.com/docJerem/ex_saml/compare/v1.0.1...v1.0.2
[1.0.1]: https://github.com/docJerem/ex_saml/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/docJerem/ex_saml/releases/tag/v1.0.0
