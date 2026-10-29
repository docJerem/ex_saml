# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `ExSaml.Core.Xml.SafeXml`, the single entry point for parsing XML: SAML messages, decrypted assertions and IdP metadata all go through `SafeXml.scan/1`, which returns `{:ok, xml}` or `{:error, :invalid_xml}` and never raises. `SafeXml.inflate/1` and `SafeXml.inflate_if_deflated/1` inflate DEFLATE-compressed messages within a size limit (#29)
- `config :ex_saml, :safe_xml` with the keys `:max_document_size`, `:max_new_atoms`, `:extra_prefixes`, `:extra_names` and `:on_error`, an arity-1 hook receiving `%{reason: :invalid_xml, kind: :error | :exit | :throw | :rejected, payload: …}` on every rejected or unparsable document, e.g. to forward it to a SIEM. See "XML parsing limits" in the README (#29)
- Encrypted assertions in AES-192-CBC, AES-192-GCM and AES-256-GCM, and with the key transported in XML Encryption 1.1 `rsa-oaep`. The `ds:DigestMethod`, `xenc11:MGF` and `xenc:OAEPparams` of an RSA-OAEP `EncryptedKey` are now honoured, so a key wrapped with RSA-OAEP over SHA-256 decrypts; they used to be ignored and every such assertion was rejected with `:bad_assertion`
- `config :ex_saml, :enforced_response_checks` lists the response checks that reject a response: `:all` (the default) enforces every check, `[]` makes every check but `:duplicate` log-only, an explicit list enforces exactly the checks it names, plus `:duplicate`, which no policy downgrades. A check that is not enforced logs one `[ExSaml] saml_validation check=… enforced=false expected=… actual=…` line and lets the sign-in go on. See "Response validation checks" in the README (#55)
- `ExSaml.AssertionReplayCache`, which records the consumed assertion IDs in the configured cache until the assertion would be stale, plus the clock skew. `ExSaml.SPHandler` uses it on every response; `ExSaml.AssertionReplayCache.duplicate_fun/1` can be passed to `ExSaml.Core.Sp.validate_assertion/3` (#55)
- `ExSaml.Core.ValidationContext` and `ExSaml.Core.Saml.validate_assertion/2`, which validates an assertion against it; `ExSaml.Core.SpConfig` gains `idp_entity_id`, `idp_id` (filled from `%ExSaml.IdpData{}`) and `SpConfig.entity_id/1`; `ExSaml.Core.Sp.xml_id/1` reads back the ID of a generated request, which `ExSaml.AuthHandler` stores in the relay state and in the session (`"authn_request_id"`). `ExSaml.Core.Assertion` gains `id`, `audience_restrictions`, `one_time_use` and `response_in_response_to` (the `Response/@InResponseTo`, also on `ExSaml.Assertion`), `ExSaml.Core.Subject` gains `notbefore` (#55)
- Error messages in English and French for `:bad_issuer`, `:bad_in_response_to`, `:bad_destination`, `:bad_subject_confirmation`, `:session_expired`, `:duplicate` (#55) and `:bad_name_id`
- `user_key_attribute` IdP option: the attribute whose value keys the signed-in user instead of the NameID, when the assertion carries it. It defaults to `"idp_user_id"`, the attribute that was read until now; `nil` keys on the NameID only. When the IdP sends several values, the first one keys the user and a warning is logged: the key is always one value, so the NameID of a logout request can match it

### Changed

- `ExSaml.Core.Binding.decode_response/2` returns `{:ok, xml}` or `{:error, :invalid_xml}` instead of the bare parsed element, and no longer raises on invalid base64, invalid DEFLATE data or malformed XML (#29)
- The `{:invalid_response, reason}` error of the sign-in and sign-out flows now carries the atom `:invalid_xml` instead of an inspected exception string (#29)
- IdP metadata is parsed with `SafeXml.scan/1` instead of `SweetXml.parse/2`. Whitespace in text nodes is no longer normalised and comments are kept in the parsed tree; the values `ex_saml` reads from metadata are trimmed as before. Metadata that cannot be parsed raises `ExSaml.ConfigError` when the provider is loaded, instead of an exit from `:xmerl_scan` (#29)
- RSA-1_5 key transport is rejected by default: `Sp.validate_assertion/2` returns `{:error, :bad_assertion}` and logs why. XML Encryption 1.1 §5.5.1 advises against RSA-1_5; an IdP that still uses it can be allowed with the new `allow_rsa_1_5_key_transport: true` IdP option
- A `SubjectConfirmation` without `@Method` decodes as `:unknown` instead of `:bearer` and is rejected with `:bad_subject_confirmation`. Every `Audience` value is read whole, including a value split by a comment, and the SP entity id must be named in every `AudienceRestriction`; `conditions[:audience]` holds the first value. An assertion without `Audience`, a signed `Response` without `Destination` and a re-posted `SAMLResponse` are rejected; each can be made log-only with `:enforced_response_checks` (#55)
- The configured cache must implement `put_new/3` (Nebulex 2 contract: `true` when written, `false` when the key exists), used by the replay check. Every Nebulex cache does; a hand-written cache module must add it (#55)
- `provider_type: :adfs`, `:ping_federate` and `:ping_one` no longer change `signed_assertion_in_resp` and `signed_envelopes_in_resp`: they keep their configured value, `signed_assertion_in_resp: true` by default. An IdP of these types that signs only the Response must be configured with `signed_assertion_in_resp: false, signed_envelopes_in_resp: true`. The other options `:adfs` sets are unchanged
- An IdP configured with both `signed_assertion_in_resp: false` and `signed_envelopes_in_resp: false` is invalid: it is logged as an error and skipped when the providers are loaded
- `NameID` and each `AttributeValue` are read as the concatenation of their text nodes, so a value split across text and CDATA sections reads whole; a value split in several text nodes used to read as `""` for `NameID` and as a list of parts for an attribute
- `ExSaml.SPHandler` rejects a sign-in with `:bad_name_id` when neither the `user_key_attribute` nor the NameID gives the user a non-blank key; it used to key every such user of the IdP on an empty NameID. The NameID itself stays optional: an assertion without one is accepted when it carries the `user_key_attribute`. A Subject/EncryptedID, which is not decrypted, is logged
- The authorization code is appended to the target URL with `URI.append_query/2`: a target URL that already has a query string keeps it (`/cb?tenant=acme&code=…`) instead of getting a second `?`
- IdP-initiated flow: when `allowed_target_urls` is not set, the RelayState is used as the redirect target only when it is a relative path (a single leading `/`, no scheme or host, no backslash or control character); any other value redirects to `/` and logs a warning. With `allowed_target_urls` set, nothing changes. An integration that relies on absolute RelayState targets in the IdP-initiated flow must list them in `allowed_target_urls`

### Security

- Reject XML documents containing a DOCTYPE declaration, or any markup declaration, before parsing, and make the parser refuse to fetch any external resource. SAML messages and metadata never carry a DOCTYPE (#29)
- Reject entity references other than the five predefined entities and character references (#29)
- Bound the size of parsed documents and of inflated messages: HTTP-Redirect messages are inflated incrementally and rejected once they exceed `:max_document_size` (1 MiB by default), and the same bound applies to HTTP-POST payloads, including those an IdP compresses (#29)
- Bound atom creation during XML parsing. Element names, attribute names, local names, namespace URIs and processing-instruction targets outside the built-in SAML, XML-DSig, XML-Enc and metadata vocabularies draw from a node-wide budget (`:max_new_atoms`, 10 000 by default), checked before the parser runs; a document that does not fit in what remains is rejected (#29)
- Reject declared encodings other than UTF-8, US-ASCII and ISO-8859-1, and UTF-16 / UTF-32 documents (#29)
- Parse IdP metadata through `SafeXml.scan/1`, with the same options and limits as SAML messages (#29)
- `Sp.validate_assertion/2` verifies the Response signature, when the IdP signs it, before decrypting an `EncryptedAssertion`
- The AES-CBC padding is removed by the length its last byte gives (XML Encryption §5.4.1), and an invalid length is rejected
- Validate the `Response/Issuer` and `Assertion/Issuer` against the IdP `entityID` (`:bad_issuer`) (#55)
- Validate `SubjectConfirmationData/@InResponseTo` and `Response/@InResponseTo` against the ID of the AuthnRequest the SP sent (`:bad_in_response_to`) (#55). A response carrying either attribute is a response to a request, never an unsolicited one
- Validate `AuthnStatement/@SessionNotOnOrAfter` (`:session_expired`) and `SubjectConfirmationData/@NotBefore` (`:too_early`), with the 5 s clock skew of `Conditions/@NotBefore` (#55)
- Require the bearer `SubjectConfirmation/@Method` (`:bad_subject_confirmation`) (#55)
- Validate the `Response/@Destination` against the ACS URL, and require it on a signed `Response` (`:bad_destination`) (#55)
- Reject an assertion whose ID was already consumed while it is still valid (`:duplicate`), whatever the `:enforced_response_checks` policy (#55)
- Require an `Audience` and evaluate every `Audience` value of every `AudienceRestriction` (`:bad_audience`) (#55)
- Require a signature on every Response: `provider_type` no longer turns off the configured signature requirements, and an IdP that requires neither an assertion nor an envelope signature is rejected at load
- Reject an assertion whose `NameID` or `AttributeValue` contains an XML comment or a processing instruction (`:bad_assertion`)
- Restrict the redirect target of the IdP-initiated flow to relative paths when `allowed_target_urls` is not set
- Remove the `https://start-from:` RelayState redirect of the assertion consumer service: a `RelayState` containing `https://start-from:` was followed as a redirect target before any validation of the `SAMLResponse`, which made the ACS an open redirect for anyone who knew an IdP id. A `RelayState` is only ever read after the response is validated
- The `target_url` parameter of `ExSaml.AuthRouter` (`/signin/:idp_id`, `/signout/:idp_id`) must be a relative path or one of the IdP's `allowed_target_urls`; any other value answers 400 `invalid target_url`. The authorization code is appended to it after the SAML exchange, so it used to be able to hand the code to any origin the caller named
- `ExSaml.Core.Xml.Dsig.verify/2` returns `{:error, :bad_signature}` for a `ds:Signature` that is not a well-formed XML-DSig — no exclusive-c14n `Transform`, several `Reference` elements, a `DigestValue`, `SignatureValue` or `X509Certificate` that does not decode — instead of raising. A crafted `SAMLResponse` could make the ACS answer 500 instead of redirecting with an error

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
