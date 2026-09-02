# Error handling and debugging

This guide is for applications that integrate `ex_saml`. It covers:

1. [The callback contract](#1-the-callback-contract): `code` on success, `error_id` on failure
2. [`%ExSaml.Error{}` reference](#2-exsamlerror-reference) and the catalogue of reasons
3. [Legacy behaviour](#3-legacy-behaviour): the `ex_saml_error` session entry
4. [Debug mode](#4-debug-mode): enabling it at runtime and reading a report
5. [Troubleshooting recipes](#5-troubleshooting-recipes)

## 1. The callback contract

After the IdP posts its `SAMLResponse` to the assertion consumer service (ACS),
`ExSaml.SPHandler.consume_signin_response/1` always redirects the browser to
the target URL with **exactly one** of these query parameters:

| Outcome | Redirect | Redeem with |
|---|---|---|
| Success | `<target_url>?code=<authorization_code>` | `ExSaml.Assertion.get_from_code/1` |
| Failure | `<target_url>?error_id=<id>` | `ExSaml.Error.get_from_id/1` |

Both identifiers are random, **single-use** (the first redemption deletes the
entry) and **expire**:

| Entry | Default TTL | Config |
|---|---|---|
| authorization code | 30 s | `ExSaml.AuthorizationCodeCache.ttl/0` |
| error | 5 min | `config :ex_saml, error_ttl: :timer.minutes(5)` |

Both live in the cache configured with `config :ex_saml, cache: MyApp.Cache`, so
they resolve on any node sharing that cache. Neither depends on the browser
session, which is deliberate: the IdP POST is cross-site, and session cookies
are not a reliable channel across it.

A Phoenix controller handling both outcomes:

```elixir
defmodule MyAppWeb.SamlCallbackController do
  use MyAppWeb, :controller
  require Logger

  def callback(conn, %{"code" => code}) do
    case ExSaml.Assertion.get_from_code(code) do
      {:ok, {idp_id, attributes}} ->
        conn |> sign_in(idp_id, attributes) |> redirect(to: "/")

      {:error, :unauthorized} ->
        # code unknown, expired or already consumed
        conn |> put_flash(:error, "Please sign in again") |> redirect(to: "/login")

      {:error, assertion: :not_found} ->
        # code was valid but the assertion is gone from the assertion store
        conn |> put_flash(:error, "Please sign in again") |> redirect(to: "/login")
    end
  end

  def callback(conn, %{"error_id" => error_id}) do
    case ExSaml.Error.get_from_id(error_id) do
      {:ok, %ExSaml.Error{} = error} ->
        Logger.warning("SAML sign-in failed",
          reason: inspect(error.reason),
          step: error.step,
          idp_id: error.idp_id,
          saml_sub_status: error.saml_sub_status
        )

        conn
        |> put_flash(:error, ExSaml.ErrorMessages.get(error))
        |> redirect(to: "/login")

      {:error, :not_found} ->
        # expired or already consumed
        redirect(conn, to: "/login")
    end
  end

  def callback(conn, _params), do: redirect(conn, to: "/login")
end
```

## 2. `%ExSaml.Error{}` reference

| Field | Type | Meaning |
|---|---|---|
| `reason` | term | The error produced by the library (see catalogue below). Unchanged vocabulary: pattern-match on it as you always did. |
| `step` | atom | Where the flow stopped: `:idp_lookup`, `:decode`, `:validate_authresp`, `:target_url`, `:unexpected` |
| `flow` | `:sp_initiated \| :idp_initiated \| nil` | Known once the assertion was decoded |
| `idp_id` | binary | The IdP the response was for |
| `relay_state` | binary | The `RelayState` received with the response |
| `saml_status` | atom | Top-level IdP `StatusCode` (`:responder`, `:requester`, …) when `reason` is `{:saml_error, _, _}` |
| `saml_sub_status` | atom | Nested IdP `StatusCode` (`:authn_failed`, `:invalid_nameid_policy`, …), see `ExSaml.Core.StatusCode` |
| `debug_id` | binary | Key of the debug report for this flow, when debug was on |
| `node` | atom | Node that consumed the response |
| `at` | `DateTime` | When the error was issued |
| `details` | list | The full debug report (`ExSaml.Debug.report/1`) when debug was on, else `nil` |

`ExSaml.ErrorMessages.get/2` accepts the struct (or the bare `reason`) and
returns a translated, user-facing message (`"en"` and `"fr"`). It never raises:
an unknown code yields the generic `unknown_error` message and a warning log.

### Catalogue of reasons

Step `:idp_lookup`

| Reason | Meaning |
|---|---|
| `{:unknown_idp, idp_id}` | No identity provider is configured under that id |

Step `:decode` (payload and XML)

| Reason | Meaning |
|---|---|
| `:missing_saml_response` | No `SAMLResponse` form field |
| `{:invalid_response, msg}` | Base64 / DEFLATE / XML parsing failed |
| `:bad_saml` | No `Status` element |
| `{:saml_error, status_uri, message}` | The IdP reported a non-success status. Look at `saml_sub_status` for the actionable code (`:authn_failed`, `:request_denied`, `:invalid_nameid_policy`, `:unknown_principal`, `:no_passive`, …). |
| `:bad_assertion` | Not exactly one readable `Assertion` (missing, multiple, or decryption failed) |
| `{:envelope, {:error, e}}` | The `Response` signature failed: `e` is `:no_signature`, `:missing_certificate` (no `X509Certificate` in `KeyInfo`), `:bad_digest`, `:bad_signature`, `:cert_not_accepted`, `:multiple_signatures`, `:insecure_algorithm` or `:unsupported_algorithm` |
| `{:assertion, {:error, e}}` | Same for the `Assertion` signature |
| `:bad_version` | Not SAML 2.0 |
| `:bad_recipient` | `SubjectConfirmationData/@Recipient` ≠ ACS URL |
| `:bad_audience` | `AudienceRestriction` ≠ SP entity id |
| `:too_early` | `NotBefore` in the future (5 s skew tolerated) |
| `:stale_assertion` | `NotOnOrAfter` in the past |
| `:duplicate` | Rejected by the configured duplicate-detection function |

Step `:validate_authresp` (flow)

| Reason | Meaning |
|---|---|
| `:idp_initiated_not_allowed` | Empty `InResponseTo` but `allow_idp_initiated_flow` is off |
| `:invalid_relay_state` | The `RelayState` does not match what the SP issued (session or relay-state cache) |
| `:invalid_idp_id` | The IdP that answered is not the one that was asked |

Step `:target_url`

| Reason | Meaning |
|---|---|
| `:invalid_target_url` | IdP-initiated flow with a `RelayState` outside `allowed_target_urls` |

Step `:unexpected`

| Reason | Meaning |
|---|---|
| `{:exception, message}` | Something raised while consuming the response. The library fails closed with an `error_id` instead of a bare 500; the stack trace is in the server logs and, in debug mode, in `details`. |

## 3. Legacy behaviour

The failure path still writes `{:error, reason}` under the `"ex_saml_error"`
session key, so consumers that read it keep working. Do not rely on it for new
code: the IdP POST is cross-site, so depending on cookie settings the session
written there may not be the one your callback reads, and you end up with
neither a `code` nor an error. `error_id` has no such dependency.

## 4. Debug mode

`ExSaml.Debug` traces every decision point of the sign-in flow and stores a
per-flow report. It is meant for production diagnostics.

### Enabling it at runtime

The flag lives in the cache configured with `config :ex_saml, cache:`. It is
enabled **at runtime, without a redeploy, a restart or a config change**, and it
is visible to every node sharing that cache:

```elixir
# From a remote console (`bin/my_app remote`) or an rpc:
#   bin/my_app rpc 'ExSaml.Debug.enable(idp_id: "acme", ttl: :timer.minutes(30))'

ExSaml.Debug.enable(ttl: :timer.minutes(30))                  # every IdP
ExSaml.Debug.enable(idp_id: "acme", ttl: :timer.minutes(30))  # one IdP only
ExSaml.Debug.status()
#=> %{global: false, static: false, idps: ["acme"], expires_in_ms: %{{:idp, "acme"} => 1799812}}
ExSaml.Debug.disable("acme")
ExSaml.Debug.disable()
```

- Default: **off**.
- Scope: global, or a single `idp_id` (recommended in production).
- **Auto-expiry**: the flag always expires, default 1 hour.
- `config :ex_saml, debug: true` is a static override for dev/test only.
- Without a configured cache, `enable/1` falls back to a node-local toggle with
  the same TTL.
- Debug can never break a sign-in: every cache failure inside `ExSaml.Debug`
  degrades to "disabled".

> **PII warning.** In debug mode the raw `SAMLResponse`, the NameID and the
> assertion attributes are written to the logs and to the report. Keep the TTL
> short and scope to one IdP whenever possible.

### What gets captured

Each step is logged at `:warning` level as `[ExSaml.Debug] <step> %{…}` with the
whole context in the message body (no logger formatter change required), and
appended to the flow report.

| Step | Where | Captured |
|---|---|---|
| `:authn_request` | AuthnRequest sent | idp_id, relay_state, target_url, nonce and its source (`:assigns` / `:cookie` / `:generated`), binding, IdP URL, whether a session id / user token was present |
| `:response_received` | ACS entry | relay_state (raw / decoded), relay-state cache hit and content, method, host, origin / referer / user-agent, cookie names, body param keys, `SAMLEncoding`, raw `SAMLResponse`, which session keys were present |
| `:saml_status_error` | IdP non-success status | top-level and nested `StatusCode`, `StatusMessage`, `StatusDetail` |
| `:validate_assertion_failed` | XML validation | the reason, and for `:bad_assertion` which extraction path failed (`where:`) with the swallowed exception |
| `:decode_payload_failed` | payload decoding | encoding, payload size, exception with stack trace |
| `:decode_result` | after decoding | the full decoded assertion, or the reason |
| `:validate_authresp_result` | flow validation | result, and the **provenance** (`:session` / `:cache` / `:none`) of the expected relay_state, idp_id and nonce |
| `:code_issued` | success | code, assertion key, nonce, flow, target URL and its source |
| `:code_stored` / `:code_taken` | `ExSaml.AuthorizationCodeCache` | code, hit / miss, value, remaining TTL. This is where a double redemption shows up. |
| `:code_redeemed` | `ExSaml.Assertion.get_from_code/1` | code found?, assertion found?, assertion |
| `:relay_state_taken` / `:relay_state_deleted` | `ExSaml.RelayStateCache` | key, hit / miss |
| `:error_issued` | failure | error_id, reason, step, target URL and its source, session snapshot |
| `:unexpected_error` | rescued exception | formatted exception with stack trace |
| `:logout_response_failed` / `:logout_request_failed` | single logout | error, payload |

### Reading a report

The report key (`debug_id`) is the `RelayState` for SP-initiated flows. It is
never put in a URL: on success it is inside the authorization code payload
(`debug_id:` key, `nil` when debug is off); on failure it is
`%ExSaml.Error{debug_id: _}` and the report is already embedded in `details`.

```elixir
{:ok, %ExSaml.Error{debug_id: id, details: details}} = ExSaml.Error.get_from_id(error_id)
ExSaml.Debug.report(id)
#=> [
#     {:authn_request, %{relay_state: "…", nonce_source: :cookie, …}},
#     {:response_received, %{relay_cache_hit: true, session: %{relay_state: nil, …}, …}},
#     {:decode_result, %{result: :error, reason: {:assertion, {:error, :bad_digest}}}},
#     {:error_issued, %{error_id: "…", step: :decode, …}}
#   ]
```

Reports expire after `config :ex_saml, debug_report_ttl:` (default 15 minutes).

## 5. Troubleshooting recipes

**"Code not found at callback"** (`get_from_code/1` → `{:error, :unauthorized}`,
or your own `AuthorizationCodeCache.take/1` returns `nil`)

Enable debug for the IdP, reproduce, then read the report:

- two `:code_taken` entries for the same code, the second with `hit: false` →
  the callback URL was requested twice (browser prefetch, link scanner, refresh,
  double submit). The first request did sign the user in.
- `:code_stored` present, single `:code_taken` with `hit: false` and a
  `remaining_ttl` of `nil` → the code expired (30 s) or was written on a node
  whose cache is not shared with the node serving the callback.
- no `:code_stored` at all → the IdP response never reached `:code_issued`;
  look for `:error_issued` instead and handle `error_id` in your callback.

**"error_id but the session is empty"**

Expected: the failure path no longer needs the session. Read
`%ExSaml.Error{}`; `details.response_received.session` shows what the ACS
request could see, and `relay_cache_hit` whether the server-side relay state
was still there.

**`:invalid_relay_state`**

`:validate_authresp_result` shows `relay_state_expected` and its source. `:none`
means neither the session nor the relay-state cache had it: the AuthnRequest is
older than 5 minutes, or it was issued on a node that does not share the cache.

**`:bad_assertion`**

`:validate_assertion_failed` carries `where:` — `:assertion_count` (0 or several
`Assertion` elements), `:decrypted_assertion_count`, or `:decrypt_assertion`
with the exception (wrong SP key, unsupported cipher).

**`{:saml_error, …}` from the IdP**

`saml_sub_status` is the code to act on: `:authn_failed` (user could not
authenticate), `:request_denied` (user not entitled to the app),
`:invalid_nameid_policy` (NameID format mismatch), `:unknown_principal`,
`:no_passive`. `:saml_status_error` also carries the IdP's `StatusMessage`.
