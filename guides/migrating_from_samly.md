# Migrating from Samly to ExSaml

This guide covers migrating from [Samly](https://hex.pm/packages/samly) (or the [Dropbox fork](https://github.com/dropbox/samly)) to ExSaml. ExSaml is the actively maintained successor — the Dropbox fork has been [declared unmaintained](https://github.com/dropbox/samly/pull/23#issuecomment-2537921498).

## Dependencies

Update your `mix.exs`:

```elixir
# Old
{:samly, "~> 1.4"}

# New
{:ex_saml, "~> 1.0"}
```

ExSaml requires **Elixir ~> 1.15** (up from ~> 1.10) and adds new dependencies: `nebulex`, `elixir_uuid`, and `gettext`.

## Module Renaming

All modules follow the pattern `Samly.*` -> `ExSaml.*`:

| Samly | ExSaml |
|-------|--------|
| `Samly` | `ExSaml` |
| `Samly.Assertion` | `ExSaml.Assertion` |
| `Samly.AuthHandler` | `ExSaml.AuthHandler` |
| `Samly.Provider` | `ExSaml.Provider` |
| `Samly.Router` | `ExSaml.Router` |
| `Samly.State` | `ExSaml.State` |
| `Samly.State.ETS` | `ExSaml.State.ETS` |
| `Samly.State.Session` | `ExSaml.State.Session` |
| `Samly.State.Store` | `ExSaml.State.Store` |
| `Samly.SPRouter` | **Removed** (consolidated) |

## Configuration

Replace all `:samly` config keys with `:ex_saml`:

```elixir
# Old
config :samly, Samly.Provider,
  idp_id_from: :path_segment,
  service_providers: [...],
  identity_providers: [...]

config :samly, Samly.State,
  store: Samly.State.ETS

# New
config :ex_saml, ExSaml.Provider,
  idp_id_from: :path_segment,
  service_providers: [...],
  identity_providers: [...]

config :ex_saml, ExSaml.State,
  store: ExSaml.State.ETS  # or ExSaml.State.Session or ExSaml.State.Cache (new)
```

### New: Cache Configuration

ExSaml uses Nebulex for relay state and assertion caching. Configure the cache module:

```elixir
config :ex_saml, cache: MyApp.Cache
```

### New: Dynamic Provider Loading

Providers can now be loaded from a database at runtime instead of static config:

```elixir
config :ex_saml,
  service_providers_accessor: &MyApp.Saml.service_providers/0,
  identity_providers_accessor: &MyApp.Saml.identity_providers/0
```

## Session and Conn Keys

All internal keys are renamed:

| Context | Samly | ExSaml |
|---------|-------|--------|
| Session | `"samly_assertion_key"` | `"ex_saml_assertion_key"` |
| conn.private | `:samly_idp` | `:ex_saml_idp` |
| conn.private | `:samly_nonce` | `:ex_saml_nonce` |
| conn.private | `:samly_target_url` | `:ex_saml_target_url` |
| conn.private | `:samly_assertion` | `:ex_saml_assertion` |

Update any code that reads these keys directly.

## Router Changes

### Forwarding

```elixir
# Old
forward "/sso", Samly.Router

# New
forward "/sso", ExSaml.Router
```

### Removed: GET Routes

Samly exposed `GET /auth/signin/:idp_id` and `GET /auth/signout/:idp_id` that rendered an HTML form to initiate SSO. These are **removed** in ExSaml.

Use `POST` endpoints directly, or use the new `ExSaml.AuthHandler.request_idp/2` function in your controller:

```elixir
# Direct IdP request from a controller (replaces GET form initiation)
def sso_login(conn, %{"idp_id" => idp_id}) do
  ExSaml.AuthHandler.request_idp(conn, idp_id)
end
```

### Removed: SPRouter

`Samly.SPRouter` is removed. SP endpoints (metadata, consume, logout) are consolidated into the main router structure.

## Changed Defaults

Some IdpData defaults have changed. Review your IdP configurations:

| Setting | Samly Default | ExSaml Default |
|---------|--------------|----------------|
| `signed_envelopes_in_resp` | `true` | `false` |
| `allow_idp_initiated_flow` | `false` | `true` |

If you relied on the old defaults, set them explicitly in your IdP config.

## Removed Features

### pre_session_create_pipeline

Samly allowed a custom Plug pipeline to run before storing the assertion:

```elixir
# Old (no longer supported)
%{
  id: "my_idp",
  pre_session_create_pipeline: MyApp.SamlPipeline
}
```

ExSaml's `SPHandler.consume_signin_response/2` now returns a structured result instead:

```elixir
{:ok, %{assertion: assertion, nonce: nonce, user_token: token, redirect_uri: uri}}
```

Move your custom assertion processing logic to the code that calls `consume_signin_response/2`.

### debug_mode

The `debug_mode: true` IdP option that returned raw SAML XML on errors is removed. Use application-level logging for SAML debugging instead.

## New Features

These are additions you can optionally adopt:

| Feature | Description |
|---------|-------------|
| `ExSaml.State.Cache` | Nebulex-based assertion store (distributed-friendly) |
| `ExSaml.SecurityPlug` | Extracted security headers plug with CSP nonce |
| `ExSaml.RelayStateCache` | TTL-based relay state with anti-replay (`take/1`) |
| `ExSaml.AuthHandler.request_idp/2` | Direct IdP request without HTML form |
| `remove_saml_encoding` | IdP option for LemonLDAP compatibility |
| `use_redirect_for_slo` | IdP option to use HTTP-Redirect for Single Logout |
| Provider-type defaults | Per-IdP-type defaults (ADFS, PingFederate, IBM, etc.) |
| Dynamic provider loading | Load SP/IdP configs from database at runtime |
| i18n error messages | Gettext-based localized error messages |

## Migration Checklist

- [ ] Replace `{:samly, ...}` with `{:ex_saml, "~> 1.0"}` in `mix.exs`
- [ ] Ensure Elixir >= 1.15
- [ ] Rename all `Samly.*` module references to `ExSaml.*`
- [ ] Replace `:samly` config keys with `:ex_saml`
- [ ] Update session key references (`samly_assertion_key` -> `ex_saml_assertion_key`)
- [ ] Update `conn.private` key references (`samly_*` -> `ex_saml_*`)
- [ ] Update router: `forward "/sso", ExSaml.Router`
- [ ] Remove GET `/signin` and `/signout` route handling, use `request_idp/2` or POST
- [ ] Remove `pre_session_create_pipeline` from IdP configs
- [ ] Remove `debug_mode` from IdP configs
- [ ] Review changed defaults (`signed_envelopes_in_resp`, `allow_idp_initiated_flow`)
- [ ] Configure Nebulex cache if using `ExSaml.State.Cache`
- [ ] Test authentication flow end-to-end
