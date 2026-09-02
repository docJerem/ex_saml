# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Breaking

- **One error shape everywhere: `{:error, %ExSaml.Error{}}`.** `ExSaml.SPHandler.consume_signin_response/2`, `ExSaml.Assertion.get_from_code/1` and `ExSaml.Error.get_from_id/1` no longer return bare terms of assorted shapes (`:bad_audience`, `{:envelope, {:error, :no_signature}}`, `{:saml_error, uri, message}`, `{:invalid_response, "…"}`, `{:error, :unauthorized}`, `{:error, assertion: :not_found}`). `reason` is always an atom from a closed catalogue, and nothing the tuples carried is lost: the element goes to `scope` (`:envelope` / `:assertion`), the IdP status to `saml_status` / `saml_status_uri` / `saml_sub_status` / `saml_message`, free text to `detail`, the IdP id to `idp_id`. `ExSaml.Error.from_reason/2` is the single normalisation point and `ExSaml.Error.to_legacy/1` rebuilds the old term for incremental migration. `get_from_code/1` failures are `:authorization_code_not_found` / `:assertion_not_found` with `step: :code_exchange`; `get_from_id/1` misses are `:error_not_found` with `step: :error_lookup`. The legacy `ex_saml_error` session entry now holds the struct. See "Upgrading to 2.0" in `guides/error_handling_and_debugging.md` (#54)
- **`trace_id` is the identifier of every flow and of every error.** Every sign-in flow gets a `trace_id` (the `RelayState` for SP-initiated flows, a fresh id otherwise) whether debug is on or off. It is the identifier of `%ExSaml.Error{}` (field `trace_id`), the value of the `?error_id=` redirect parameter, the key of the `ExSaml.Debug` trace and capture, and an additive `trace_id:` key in the authorization code payload and in the success map of `consume_signin_response/2` (#54)

### Added

- `error_id` callback contract, symmetric with the authorization `code`: when the assertion consumer service cannot complete a sign-in, `ExSaml.SPHandler` stores the `%ExSaml.Error{}` in the new `ExSaml.ErrorCache` (single-use, 5 min TTL, `config :ex_saml, error_ttl:`) and redirects to `target_url?error_id=<trace_id>`. Consumers look it up with `ExSaml.Error.get_from_id/1`, without depending on the browser session across the cross-site IdP POST. The struct carries `trace_id`, `reason`, `scope`, `step`, `flow`, `idp_id`, `relay_state`, the `saml_*` status fields, `detail`, `node`, `at` and `trace` (#54)
- `ExSaml.Debug`: runtime debug mode stored in the configured Nebulex cache (or a dedicated `config :ex_saml, debug_cache:`). `enable/1` (global or `idp_id:`, always with a TTL, default 1 h; `capture:` `:on_error` | `:always` | `:none`; `log:` `:steps` | `:full` | `:silent`), `disable/1`, `status/0`, `enabled?/1`, `settings/1`. Enabled from a remote console or `bin/app rpc` without a redeploy, restart or config change; visible to every node sharing the cache; auto-expiring; never breaks the auth flow when the cache fails. Static override `config :ex_saml, debug: true | [capture: …, log: …]` for dev/test; node-local fallback when no cache is configured (#54)
  - **Traces** (`ExSaml.Debug.trace/1`, `config :ex_saml, trace_ttl:` default 15 min): every decision point of the flow is logged (`debug_log_level`, default `:warning`; `log: :steps` redacts the payload, the assertion and the NameID from the log lines) and recorded — AuthnRequest, ACS request (size of the `SAMLResponse`, cookie names, session snapshot, relay-state cache hit), decoding, IdP status, validation with the provenance (session vs cache) of relay_state / idp_id / nonce, code issuance, code storage and exchange, error issuance, logout failures.
  - **Captures** (`ExSaml.Debug.failure/1`, `failures/1`, `capture/1`, `saml_response/2`): the diagnostic record of a failed flow — error summary without PII plus the raw `SAMLResponse` (base64 exactly as posted, decoded on read), `saml_encoding`, `relay_state`, `consume_uri`, `entity_id`, `received_at`, `captured_on`. With `capture: :on_error` the record is written at receipt with a short TTL (`provisional_ttl`, default 2 min) and promoted (`payload_ttl`, default 1 h, indexed per IdP, `max_failures_per_idp` default 20) when the library rejects the response **or when the authorization code is later not found at exchange** — the "signed in on the library side, failed on the consumer side" case. `:none` keeps a record without the payload.
  - **Replay** (`ExSaml.Debug.replay/2`): runs a captured `SAMLResponse` through the live decoding and validation against the current IdP configuration, with the captured `consume_uri` / `entity_id`, and evaluates time conditions as of the instant of receipt (`now:` option threaded through `ExSaml.Core.Sp.validate_assertion/4` and `ExSaml.Core.Saml.validate_assertion/4`). Returns `{:ok, assertion}` or `{:error, %ExSaml.Error{step: :replay | :decode}}` (`:capture_not_found`, `:payload_not_captured`).
- `ExSaml.Core.StatusCode`: full catalogue of the 23 SAML 2.0 `StatusCode` URIs (4 top level, 19 second level) with `to_atom/1`, `to_uri/1`, `top_level?/1`, `second_level?/1`. `ExSaml.Core.Sp` now reads the nested second-level `StatusCode`, `StatusMessage` and `StatusDetail` of a non-success response and exposes them through `%ExSaml.Error{}` and `ExSaml.ErrorMessages` (#54)
- English consumer guide `guides/error_handling_and_debugging.md`: callback contract and `trace_id`, `%ExSaml.Error{}` reference and catalogue of reasons, 2.0 migration, debug mode (traces, captures, replay), troubleshooting recipes (#54)
- `ExSaml.ErrorMessages` (en/fr) now covers every reason produced on the sign-in path, every signature verification error, the code-exchange / error-lookup / replay reasons and every second-level SAML status (#54)

### Fixed

- Signature verification no longer crashes with a `MatchError` when the IdP signs without embedding its X.509 certificate in `KeyInfo`: `ExSaml.Core.Xml.Dsig.verify/2` returns `{:error, :missing_certificate}`, surfaced as `%ExSaml.Error{reason: :missing_certificate, scope: _}` and translated (en/fr) by `ExSaml.ErrorMessages` (#51)

### Changed

- `ExSaml.SPHandler.consume_signin_response/1` fails closed: an unknown `idp_id` yields `reason: :unknown_idp` (`step: :idp_lookup`), a missing `SAMLResponse` yields `:missing_saml_response`, and any exception raised while consuming the response is rescued, logged, and turned into an `error_id` redirect with `reason: :exception` and the message in `detail` (`step: :unexpected`) instead of a bare 500 (#54)
- `ExSaml.ErrorMessages.get/2` no longer raises on an unknown code: it returns the generic `unknown_error` message and logs the raw code at `:warning`. It accepts `%ExSaml.Error{}`, bare atoms and every legacy term, and resolves IdP statuses through the status catalogue instead of an exact match on `:undefined` messages that never matched (#54)
- `ExSaml.Assertion.get_from_code/1` accepts both payload shapes stored under a code (the `{idp_id, name_id}` key or the map minted by `ExSaml.SPHandler`) and logs a missing / expired code at `:warning` (was `:info`) with the code (#54)
- `ExSaml.Core.Sp.validate_assertion/3,4` and `ExSaml.Core.Saml.validate_assertion/4` accept a `now:` option (additive) (#54)
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
