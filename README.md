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

### Error handling

The assertion consumer service always redirects to the target URL with either
`?code=<authorization_code>` (success) or `?error_id=<trace_id>` (failure). Both
are random, single-use and expire; consume them with `ExSaml.Assertion.get_from_code/1`
and `ExSaml.Error.get_from_id/1`. Every failure is an `%ExSaml.Error{}` whose
`reason` is always an atom and whose identifier is the flow's `trace_id`:

```elixir
def callback(conn, %{"error_id" => error_id}) do
  case ExSaml.Error.get_from_id(error_id) do
    {:ok, %ExSaml.Error{trace_id: trace_id} = error} ->
      conn
      |> put_flash(:error, "#{ExSaml.ErrorMessages.get(error)} (trace ID: #{trace_id})")
      |> redirect(to: "/login")

    {:error, %ExSaml.Error{reason: :error_not_found}} ->
      redirect(conn, to: "/login")
  end
end
```

See the [error handling and debugging guide](guides/error_handling_and_debugging.md)
for the full contract, the catalogue of reasons and the 2.0 migration notes.

### Response validation checks

Beyond signatures, recipient, audience and time conditions, the ACS checks the
`Issuer`, the `InResponseTo`, the `SessionNotOnOrAfter` and the bearer
confirmation method of every response (SAML 2.0 Core / Profiles). Each check
can reject or only log, per `config :ex_saml, enforced_response_checks:`;
`[]` turns everything log-only. Details and defaults in the
[guide](guides/error_handling_and_debugging.md#response-validation-checks).

### Debug mode

`ExSaml.Debug` records a trace of the whole sign-in flow (AuthnRequest, IdP
response, decoding, validation, code issuance and exchange), keeps a capture of
failed flows (error summary + raw `SAMLResponse`), lists them per IdP and can
replay them against the current configuration. It is enabled **at runtime**,
from a remote console, without a redeploy or a config change, globally or for
one IdP, and always expires:

```elixir
ExSaml.Debug.enable(idp_id: "acme", ttl: :timer.minutes(30))
ExSaml.Debug.enable(idp_id: "acme", capture: :always, log: :silent)
ExSaml.Debug.status()
ExSaml.Debug.failures("acme")
ExSaml.Debug.trace(trace_id)
ExSaml.Debug.saml_response(trace_id, decode: true)
ExSaml.Debug.replay(trace_id)
ExSaml.Debug.disable("acme")
```

By default the log lines redact the payload and the assertion (`log: :steps`)
and the `SAMLResponse` is kept only for flows that fail (`capture: :on_error`),
including flows whose authorization code is never exchanged. Use
`config :ex_saml, debug_cache:` to keep debug data out of your main cache.
Details in the [guide](guides/error_handling_and_debugging.md#4-debug-mode).

All of that is also reachable over HTTP, so support can diagnose a failed
sign-in without a remote console. `ExSaml.DebugRouter` is a `Plug.Router` you
mount behind your own admin pipeline — it does no authentication of its own and
refuses to start without an explicit access rule:

```elixir
forward "/", ExSaml.DebugRouter, authorize: {MyApp.Saml.Debug, :authorize}
```

`authorize` may return `{:ok, [idp_id]}` to scope every route to one tenant's
IdPs. See the [debug API guide](guides/debug_api.md).

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

`ExSaml.DebugRouter` is mounted separately, behind your admin pipeline — see
[Debug mode](#debug-mode).

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

- **XXE protection** — All XML parsing uses `allow_entities: false` ([CVE-2026-28809](https://cna.erlef.org/cves/CVE-2026-28809.html))
- **NotBefore validation** — Assertions are rejected if issued in the future (with 5s clock skew tolerance)
- **Algorithm whitelist** — Unknown signature algorithms return a clean error instead of crashing; RSA-SHA1 is rejected
- **Namespace-conformant parsing** — All `xmerl_scan` calls enforce `namespace_conformant: true`

To report a security issue, email security@cryptr.co.

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
