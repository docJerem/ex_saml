# ExSaml

[![Hex.pm](https://img.shields.io/hexpm/v/ex_saml.svg)](https://hex.pm/packages/ex_saml)
[![Docs](https://img.shields.io/badge/hex-docs-blue.svg)](https://hexdocs.pm/ex_saml)

SAML 2.0 Service Provider (SP) library for Elixir/Phoenix applications.

Originally built from the [Samly](https://hex.pm/packages/samly) codebase (by [handnot2](https://github.com/handnot2/samly)), before the [Dropbox fork](https://github.com/dropbox/samly) was created. Dropbox's fork has since been [declared unmaintained](https://github.com/dropbox/samly/pull/23#issuecomment-2537921498). ExSaml is the actively maintained successor, with enhanced security, configurable caching, and streamlined routing.

## Features

- SP-initiated and IdP-initiated SSO flows
- Single Logout (SLO) support
- SP metadata generation
- Multi-IdP support with per-IdP configuration
- IdP identification via path segment or subdomain
- Pluggable assertion storage (ETS, Session, Nebulex cache)
- Relay state cache with anti-replay protection
- Security headers plug (CSP with nonce, X-Frame-Options, etc.)
- Support for many IdP types: ADFS, Azure AD, Google, Keycloak, Okta, OneLogin, PingFederate, PingOne, IBM Security Verify, LemonLDAP

## Installation

Add `ex_saml` to your dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:ex_saml, "~> 1.0"}
  ]
end
```

## Configuration

### Service Provider

```elixir
config :ex_saml, ExSaml.Provider,
  service_providers: [
    %{
      id: "my_sp",
      entity_id: "urn:myapp:sp",
      certfile: "path/to/sp.crt",
      keyfile: "path/to/sp.key",
      # Optional
      contact_name: "Admin",
      contact_email: "admin@example.com",
      org_name: "My Org",
      org_displayname: "My Organization",
      org_url: "https://example.com"
    }
  ]
```

You can also provide `cert` and `key` directly instead of file paths.

### Identity Provider

```elixir
config :ex_saml, ExSaml.Provider,
  identity_providers: [
    %{
      id: "my_idp",
      sp_id: "my_sp",
      base_url: "https://myapp.example.com",
      metadata_file: "path/to/idp_metadata.xml",
      # Or inline: metadata: "<EntityDescriptor ...>",
      nameid_format: :email,
      sign_requests: true,
      sign_metadata: true,
      signed_assertion_in_resp: true,
      signed_envelopes_in_resp: false,
      # Only for an IdP that still encrypts with RSA-1_5 (see Security)
      allow_rsa_1_5_key_transport: false,
      # Only for an IdP that encrypts with AES-CBC and does not sign the Response (see Security)
      allow_unsigned_cbc: false,
      allow_idp_initiated_flow: true,
      use_redirect_for_req: false,
      use_redirect_for_slo: false,
      # The IdP signs its LogoutResponses (false: a signature is verified only when present)
      idp_signs_logout_responses: true,
      allowed_target_urls: ["https://myapp.example.com/dashboard"],
      # Attribute whose value keys the user instead of the NameID (nil: NameID only)
      user_key_attribute: "idp_user_id"
    }
  ],
  idp_id_from: :path_segment  # or :subdomain
```

Supported `nameid_format` values: `:email`, `:x509`, `:windows`, `:krb`, `:persistent`, `:transient`.

In the IdP-initiated flow the `RelayState` is the redirect target. With
`allowed_target_urls`, it must be one of the listed URLs; without it, only a
relative path (such as `/dashboard`) is followed and any other value redirects
to `/`.

The signed-in user is keyed on the value of the `user_key_attribute` attribute
when the assertion carries it (`"idp_user_id"` by default), and on the NameID
otherwise. Set it to another attribute name, or to `nil` to key on the NameID
only. A sign-in for which neither gives a non-blank value is rejected with
`:bad_name_id`.

At least one of `signed_assertion_in_resp` and `signed_envelopes_in_resp` must
be `true`: an IdP configured with both set to `false` is logged as an error and
skipped. `provider_type` never changes these two options.

### State Store

Choose where authenticated assertions are stored:

```elixir
# ETS (default)
config :ex_saml, ExSaml.State,
  store: ExSaml.State.ETS

# Plug Session
config :ex_saml, ExSaml.State,
  store: ExSaml.State.Session

# Nebulex Cache
config :ex_saml, ExSaml.State,
  store: ExSaml.State.Cache
```

### Cache

Configure the Nebulex cache module used for assertions, relay state,
authorization codes and the IDs of consumed assertions (replay detection):

```elixir
config :ex_saml, cache: MyApp.Cache
```

A custom cache module must provide `put_new/3` with the Nebulex 2 contract
(`true` when the key was written, `false` when it already exists); every
Nebulex cache does.

### Dynamic Provider Loading

For loading providers from a database at runtime:

```elixir
config :ex_saml,
  service_providers_accessor: &MyApp.Saml.service_providers/0,
  identity_providers_accessor: &MyApp.Saml.identity_providers/0
```

## Setup

### Supervision Tree

Add the provider to your application's supervision tree:

```elixir
children = [
  ExSaml.Provider
]
```

### Router

Forward SAML routes in your Phoenix router:

```elixir
forward "/sso", ExSaml.Router
```

This exposes:
- `POST /sso/auth/signin/:idp_id` - Initiate sign-in
- `POST /sso/auth/signout/:idp_id` - Initiate sign-out
- `POST /sso/csp-report` - CSP violation report endpoint

The sign-in and sign-out routes take a `target_url` parameter
(x-www-form-urlencoded), the URL the browser is sent to afterwards with the
authorization code appended to its query. It must be a relative path, or one
of the IdP's `allowed_target_urls`; anything else answers 400.

SP endpoints (metadata, ACS, SLO) are configured via `ExSaml.Helper` URI builders and handled by `ExSaml.SPHandler`.

## Usage

### Requesting an IdP Directly

```elixir
ExSaml.AuthHandler.request_idp(conn, idp_id)
```

### Initiating Sign-In

```elixir
ExSaml.AuthHandler.send_signin_req(conn)
```

### Initiating Sign-Out

```elixir
ExSaml.AuthHandler.send_signout_req(conn)
```

### Retrieving the Active Assertion

```elixir
assertion = ExSaml.get_active_assertion(conn)
```

To get a specific attribute:

```elixir
email = ExSaml.get_attribute(assertion, "email")
```

The `ExSaml.Assertion` struct contains:
- `idp_id` - Identity Provider identifier
- `subject` - User identity (`name`, `in_response_to`, `notonorafter`)
- `issuer` - IdP entity ID
- `attributes` - IdP-provided attributes
- `computed` - Locally computed attributes
- `conditions` / `authn` - Additional SAML metadata

## Architecture

```
Request
  |
  v
ExSaml.Router
  |-- /auth/*      -> ExSaml.AuthRouter -> ExSaml.AuthHandler
  |-- /csp-report  -> ExSaml.CsprRouter
  |
  v
ExSaml.SecurityPlug (CSP nonce, security headers)
  |
  v
ExSaml.Provider (GenServer managing SP/IdP state)
  |
  v
ExSaml.SPHandler (metadata, ACS, SLO)
  |
  v
ExSaml.State (assertion storage: ETS | Session | Cache)
```

## Security

ExSaml includes hardened defaults for SAML processing:

- **Single hardened XML entry point** — SAML messages, decrypted assertions and IdP metadata are all parsed by `ExSaml.Core.Xml.SafeXml.scan/1`, which returns `{:ok, xml}` or `{:error, :invalid_xml}` and never raises
- **XXE protection** — Documents containing a DOCTYPE declaration are rejected before parsing (SAML never uses one), entity references other than the predefined ones are rejected, the parser runs with `allow_entities: false` ([CVE-2026-28809](https://cna.erlef.org/cves/CVE-2026-28809.html)) and never fetches external resources
- **Bounded input** — Documents and DEFLATE-compressed messages are limited to `:max_document_size` bytes (1 MiB by default); compressed messages are inflated incrementally and rejected as soon as they exceed the limit
- **Bounded atom creation** — The XML parser creates an atom per element name, attribute name and namespace; names outside the SAML, XML-DSig, XML-Enc and metadata vocabularies draw from a node-wide budget (`:max_new_atoms`) and documents exceeding it are rejected (see [XML parsing limits](#xml-parsing-limits))
- **NotBefore validation** — Assertions are rejected if issued in the future (with 5s clock skew tolerance)
- **Algorithm whitelist** — RSA-SHA256/384/512 and ECDSA-SHA256/384/512 (P-256, P-384, P-521) are accepted; an unknown signature algorithm or a malformed `ds:Signature` returns a clean error instead of crashing; RSA-SHA1 is rejected
- **Namespace-conformant parsing** — XML is parsed with `namespace_conformant: true`
- **Identity values read whole** — `NameID` and `AttributeValue` are read as the concatenation of their text nodes; an assertion whose `NameID` or `AttributeValue` contains a comment or a processing instruction is rejected with `:bad_assertion`
- **Response validation** — `Issuer`, `InResponseTo`, `Destination`, `Audience`, `SessionNotOnOrAfter`, the bearer confirmation method and its `NotBefore` are checked on every response, and an assertion is accepted only once (see [Response validation checks](#response-validation-checks))
- **Encrypted assertions** — AES-128/192/256 in GCM or CBC mode, with the key transported in RSA-OAEP (`rsa-oaep-mgf1p` or XML Encryption 1.1 `rsa-oaep`, with their digest, MGF and OAEP parameters). RSA-1_5 key transport is rejected unless an IdP is configured with `allow_rsa_1_5_key_transport: true`. When the IdP signs the Response (`signed_envelopes_in_resp: true`), its signature is verified before the assertion is decrypted. An AES-CBC assertion in a Response whose signature is not required is decrypted before anything is verified, which exposes a padding oracle: this is the `:unsigned_cbc` check (log-only by default, see [Response validation checks](#response-validation-checks)); an IdP that cannot encrypt with AES-GCM or sign the Response can be configured with `allow_unsigned_cbc: true`

To report a security issue, email security@cryptr.co.

### XML parsing limits

The defaults suit standard SAML deployments; all keys are optional and read
on every parse:

```elixir
config :ex_saml, :safe_xml,
  # Maximum size, in bytes, of a document, and of a DEFLATE-compressed
  # message once inflated.
  max_document_size: 1_048_576,
  # Names outside the built-in SAML vocabulary that documents may introduce
  # over the node's lifetime. Each new name counts once.
  max_new_atoms: 10_000,
  # Namespace prefixes an IdP uses instead of the usual ones
  # (saml, saml2, samlp, saml2p, md, ds, xenc, …), e.g. "ns2" for ns2:Assertion.
  extra_prefixes: [],
  # Further names to accept without drawing from the budget, e.g. a vendor
  # extension: its namespace URI, "xmlns:<prefix>", "<prefix>:<Name>" and "<Name>".
  extra_names: [],
  # Arity-1 function called with %{reason: :invalid_xml, kind: …, payload: …}
  # on every rejected or unparsable document.
  on_error: &MyApp.SIEM.report_xml_error/1
```

Names that are already atoms, or that belong to the SAML 2.0 (assertion,
protocol, metadata and common metadata extensions), WS-Federation metadata,
XML-DSig 1.0/1.1, exclusive c14n, XML Encryption 1.0/1.1, XML Schema instance
and `xml:` vocabularies under their usual prefixes, never draw from
`:max_new_atoms`. An IdP using other prefixes or vendor extension elements
draws from it the first time each name is seen; declare them with
`:extra_prefixes` / `:extra_names` to make them independent of the budget.
When the budget is spent, documents introducing new names are rejected
(`kind: :rejected, payload: :atom_budget_exhausted` in the `:on_error` hook)
and a warning is logged once. The budget never replenishes before the node
restarts: `ExSaml.Core.Xml.SafeXml.atom_budget/0` returns `%{used: …, max: …}`
for a metric or a health check, so the budget can be watched before it runs
out.

### Response validation checks

Beyond signatures, `Recipient` and the time conditions, the assertion consumer
service performs the checks SAML 2.0 Core, Bindings and the Web Browser SSO
Profile require of a response. Each one has an error reason of its own:

| Check | Reason | Spec |
|---|---|---|
| `Response/Issuer` and `Assertion/Issuer` match the IdP `entityID` from its metadata | `:bad_issuer` | Core §2.2.3, Profiles §4.1.4.2 |
| `Response/@InResponseTo` and `SubjectConfirmationData/@InResponseTo` match the ID of the AuthnRequest the SP sent | `:bad_in_response_to` | Core §3.2.2, Profiles §4.1.4.3 |
| `AuthnStatement/@SessionNotOnOrAfter` has not passed | `:session_expired` | Core §2.7.2 |
| `SubjectConfirmation/@Method` is present and bearer | `:bad_subject_confirmation` | Core §2.4.1.1, Profiles §4.1.4.2 |
| `Response/@Destination` equals the ACS URL when present, and is present on a signed `Response` | `:bad_destination` | Core §3.2.2, Bindings §3.5.5.2 |
| The assertion ID has not been consumed before | `:duplicate` | Profiles §4.1.4.5, Core §2.5.1.5 |
| The assertion carries an `Audience` | `:bad_audience` | Profiles §4.1.4.2 |
| `SubjectConfirmationData/@NotBefore` has passed (5 s clock skew) | `:too_early` | Core §2.4.1.2 |
| An `EncryptedAssertion` in AES-CBC comes in a `Response` whose signature is required, or the IdP has `allow_unsigned_cbc: true` (log-only by default) | `:unsigned_cbc` | XML Encryption 1.1 §6.1.1 |

Two rules are outside the policy below and always reject: an
`AudienceRestriction` that does not name the SP entity id (every
`AudienceRestriction` must name it in one of its `Audience` values, Core
§2.5.1.4) and a future `Conditions/@NotBefore`.

`config :ex_saml, :enforced_response_checks` lists the checks that reject a
response. A check absent from the list is still evaluated: a failure logs one
line and the sign-in goes on. `:duplicate` cannot be downgraded: it is
enforced whatever the list says.

```elixir
config :ex_saml, enforced_response_checks: :all   # every check above, :unsigned_cbc included
config :ex_saml, enforced_response_checks: []     # everything but :duplicate log-only
config :ex_saml, enforced_response_checks: [:bad_issuer]  # exactly these, plus :duplicate
```

The default enforces every check but `:unsigned_cbc`, which ships log-only:
look for `check=:unsigned_cbc` in the logs, move each IdP it names to AES-GCM,
to a signed `Response` or to `allow_unsigned_cbc: true`, then enforce it with
`:all`.

```
[ExSaml] saml_validation check=:bad_destination enforced=false idp_id="acme" expected="https://sp.example.com/sso/consume/acme" actual="https://sp.example.com/sso/consume/acme/"
```

`expected` and `actual` are logged verbatim. An explicit list enforces
exactly the checks it names: a check added in a later release stays log-only
until it is added to the list.

**Replay detection.** Every assertion the assertion consumer service accepts
is recorded in `ExSaml.AssertionReplayCache`, keyed by `Assertion/@ID` and its
`Issuer` (by the digest of the response when the assertion has no ID), until
the assertion would be rejected as stale: its earliest `NotOnOrAfter`, else
`IssueInstant` + 5 minutes, plus the clock skew. It uses the configured cache
through `put_new/3`, so detection spans every node sharing that cache; with a
node-local cache it is per node. `:duplicate` is enforced whatever the
policy. `ExSaml.Core.Sp.validate_assertion/2`
keeps a no-op duplicate function; a direct caller passes
`ExSaml.AssertionReplayCache.duplicate_fun(sp)` to `validate_assertion/3`.

**Deliberate failure modes.**

- A missing stored AuthnRequest ID skips the `InResponseTo` check: relay
  states written before the check existed carry none, and neither does a
  consumer that drives `ExSaml.SPHandler.validate_authresp/4` without going
  through `ExSaml.AuthHandler`.
- An unparsable `SessionNotOnOrAfter` or `SubjectConfirmationData/@NotBefore`
  logs and passes, even when the check is enforced.
- An absent `Response/Issuer` is accepted silently (the element is optional),
  and so is an absent `Destination` on an unsigned `Response`.
- The response checks run after signature verification, and the replay check
  runs last among them, so an assertion another check rejects is not recorded.

Consumers supply nothing new: the IdP `entityID` and id come from
`%ExSaml.IdpData{}`, the ACS URL and the SP entity id from its `sp_config`,
and the AuthnRequest ID is stored in the relay state and the session by
`ExSaml.AuthHandler`.

## Migrating from Samly

If you're coming from [Samly](https://hex.pm/packages/samly) or the [Dropbox fork](https://github.com/dropbox/samly), see the [Migration Guide](guides/migrating_from_samly.md) for a step-by-step walkthrough covering module renaming, config changes, removed features, and a migration checklist.

### Key Differences

- **Security Plug** - Centralized security headers with CSP nonce support
- **Configurable cache backend** - Cache module set via `config.exs` instead of hardcoded
- **Nonce validation** - Cryptographic nonce generated and validated during auth flow
- **Relay state anti-replay** - `RelayStateCache.take/1` atomically reads and deletes relay state
- **Streamlined routing** - Removed unused routes, simplified session handling

## Documentation

Full documentation is available on [HexDocs](https://hexdocs.pm/ex_saml).

## License

See [LICENSE](LICENSE) for details.
