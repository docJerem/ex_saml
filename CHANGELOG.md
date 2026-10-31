# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- **Breaking:** ExSaml requires Nebulex 3 (`{:nebulex, "~> 3.0"}`) instead of Nebulex 2. An application on Nebulex 3 could not depend on ExSaml, and ExSaml called the Nebulex 2 API on the configured cache: on Nebulex 3, `get/1` returns `{:ok, value}`, so reading a relay state such as `RelayStateCache.get(rs)[:target_url]` raised, and `take/1` returns `{:error, %Nebulex.KeyError{}}` for a missing key. All cache calls now go through one internal module that uses the Nebulex 3 API. The public functions of `ExSaml.RelayStateCache`, `ExSaml.AuthorizationCodeCache` and `ExSaml.State.Cache` keep their contract: a bare value, and `nil` for a missing key. The next release is therefore a major version
- `ExSaml.AuthorizationCodeCache.put_new!/3` returns `true`, and raises a `Nebulex.Error` with the reason `:key_already_exists` when the code already exists, as it raised `Nebulex.KeyAlreadyExistsError` on Nebulex 2. On Nebulex 3 the cache's own `put_new!/3` returns `false` instead of raising, which would have let the redirect carry a code that was never stored. The documentation, which stated `:ok` or `{:error, :already_exists}`, now describes the behaviour

### Migration

- Move the application to Nebulex 3: `{:nebulex, "~> 3.0"}`, plus the adapter package of the cache given to `config :ex_saml, cache: MyApp.Cache`, which Nebulex 3 ships separately. For the local adapter, add `{:nebulex_local, "~> 3.0"}`; the adapter module keeps its name, `Nebulex.Adapters.Local`. The cache's own configuration and calls follow the [Nebulex 3 upgrade guide](https://hexdocs.pm/nebulex/v3-0.html)
- Code that calls `ExSaml.State.Cache`, `ExSaml.RelayStateCache` or `ExSaml.AuthorizationCodeCache` needs no change. A cache module given to ExSaml that is not a Nebulex cache must now implement the Nebulex 3 functions ExSaml calls: `get!/1`, `put!/3`, `put_new!/3`, `delete!/1`, `take/1`, `ttl/1` and `get_all!/1`

## [1.2.0] - 2026-10-28

### Added

- ECDSA signatures (`ecdsa-sha256`, `ecdsa-sha384`, `ecdsa-sha512`) on the P-256, P-384 and P-521 curves. An IdP whose signing certificate holds an EC key (e.g. a PingFederate `…-EC-…` signing key) had every Response rejected with `:unsupported_algorithm`, and its key was decoded as RSA. `ExSaml.Core.Xml.Dsig.verify/2` now reads EC keys and converts the XML-DSig `r || s` `SignatureValue` (RFC 4051) to the DER form `:public_key` verifies; `sign/4` does the reverse with an EC private key. A signature method naming another key type than the certificate's is rejected with `:bad_signature` (#67, #68)
- RSA-SHA384 and RSA-SHA512 signatures (`rsa-sha384`, `rsa-sha512`, RFC 6931). An IdP signing with either had every Response rejected with `:unsupported_algorithm`; `ExSaml.Core.Xml.Dsig.verify/2` now accepts them and `sign/4` takes `:rsa_sha384` and `:rsa_sha512` (#68)

### Changed

- `ExSaml.Core.Xml.Dsig.sign/3,4` raise an `ArgumentError` for an unknown signature method, or for a private key of another type than the method names, such as an EC key with `sign/3` and its default `rsa-sha256`. They used to raise a `MatchError` for the former, and for the latter to produce a document that no verifier accepts (#68)

### Security

- ECDSA verification enforces the P-256, P-384 and P-521 whitelist the documentation states. `ExSaml.Core.Xml.Dsig.verify/2` accepted a certificate on any curve `:crypto` supports, such as secp256k1, brainpoolP256r1 or the 112-bit secp224r1, and split a `SignatureValue` of any even length in two halves; it now rejects them with `:bad_signature`, and requires each of r and s to be the curve's field size (RFC 4051) (#68)
- `ExSaml.Core.Xml.Dsig.verify/2` returns `{:error, :bad_signature}` instead of raising on a crafted certificate: an EC key with unknown, implicit or explicit curve parameters, or with a point not on its curve, and a key neither RSA nor EC (e.g. Ed25519), which was decoded as RSA. The certificate's `SubjectPublicKeyInfo` algorithm must now match the key type of the signature method (#68)

## [1.1.3] - 2026-09-30

### Fixed

- Multi-valued SAML attributes are no longer concatenated into a single unseparated string. `ExSaml.Assertion.from_core/1` turned a `group` attribute carrying `Admins` / `Developers` / `Finance` into `"AdminsDevelopersFinance"`. The "list of values" clause in `stringize/1` guards on `is_list(hd(values))`, which only held while attribute values were charlists (Erlang esaml); since the `ExSaml.Core` fork (#8) the decoder emits binaries, so a list of values fell through to `List.to_string/1`, which concatenates iodata. Such attributes are now exposed as a list of strings, as `Core.Saml.decode_assertion/1` always decoded them (#64)

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

[1.2.0]: https://github.com/docJerem/ex_saml/compare/v1.1.3...v1.2.0
[1.1.3]: https://github.com/docJerem/ex_saml/compare/v1.1.2...v1.1.3
[1.1.2]: https://github.com/docJerem/ex_saml/compare/v1.1.1...v1.1.2
[1.1.1]: https://github.com/docJerem/ex_saml/compare/v1.1.0...v1.1.1
[1.1.0]: https://github.com/docJerem/ex_saml/compare/v1.0.2...v1.1.0
[1.0.2]: https://github.com/docJerem/ex_saml/compare/v1.0.1...v1.0.2
[1.0.1]: https://github.com/docJerem/ex_saml/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/docJerem/ex_saml/releases/tag/v1.0.0
