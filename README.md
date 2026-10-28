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
      allow_idp_initiated_flow: true,
      use_redirect_for_req: false,
      use_redirect_for_slo: false,
      allowed_target_urls: ["https://myapp.example.com/dashboard"]
    }
  ],
  idp_id_from: :path_segment  # or :subdomain
```

Supported `nameid_format` values: `:email`, `:x509`, `:windows`, `:krb`, `:persistent`, `:transient`.

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

Configure the Nebulex cache module used for assertions and relay state:

```elixir
config :ex_saml, cache: MyApp.Cache
```

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
- **Algorithm whitelist** — RSA-SHA256/384/512 and ECDSA-SHA256/384/512 (P-256, P-384, P-521) are accepted; unknown signature algorithms return a clean error instead of crashing; RSA-SHA1 is rejected
- **Namespace-conformant parsing** — XML is parsed with `namespace_conformant: true`

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
and a warning is logged once.

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
