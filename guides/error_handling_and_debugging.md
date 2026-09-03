# Error handling and debugging

This guide is for applications that integrate `ex_saml`. It covers:

1. [The callback contract](#1-the-callback-contract): `code` on success, `error_id` on failure
2. [`%ExSaml.Error{}` reference](#2-exsamlerror-reference) and the catalogue of reasons
3. [Legacy behaviour and upgrading to 2.0](#3-legacy-behaviour-and-upgrading-to-20)
4. [Debug mode](#4-debug-mode): runtime activation, traces, captures, replay
5. [Troubleshooting recipes](#5-troubleshooting-recipes)

## 1. The callback contract

After the IdP posts its `SAMLResponse` to the assertion consumer service (ACS),
`ExSaml.SPHandler.consume_signin_response/1` always redirects the browser to
the target URL with **exactly one** of these query parameters:

| Outcome | Redirect | Consume with |
|---|---|---|
| Success | `<target_url>?code=<authorization_code>` | `ExSaml.Assertion.get_from_code/1` |
| Failure | `<target_url>?error_id=<trace_id>` | `ExSaml.Error.get_from_id/1` |

A `target_url` that already carries a query string keeps it: `/cb?x=1`
becomes `/cb?x=1&code=…` or `/cb?x=1&error_id=…` (`ExSaml.RouterUtil.append_query/3`).

Both identifiers are random, **single-use** (the first lookup deletes the
entry) and **expire**:

| Entry | Default TTL | Config |
|---|---|---|
| authorization code | 30 s | `ExSaml.AuthorizationCodeCache.ttl/0` |
| error | 5 min | `config :ex_saml, error_ttl: :timer.minutes(5)` |

Both live in the cache configured with `config :ex_saml, cache: MyApp.Cache`, so
they resolve on any node sharing that cache. Neither depends on the browser
session, which is deliberate: the IdP POST is cross-site, and session cookies
are not a reliable channel across it.

Every failure is an `%ExSaml.Error{}` whose `reason` is **always an atom**, and
every public function returns the same shape: `{:error, %ExSaml.Error{}}`.

### The `trace_id`

Every sign-in flow has a `trace_id` — the `RelayState` for SP-initiated flows,
a fresh id otherwise — **whether debug is on or off**. It is:

- the identifier of `%ExSaml.Error{}` and the value of `?error_id=`;
- present in the authorization code payload (`trace_id:` key) on success;
- the key of the debug trace, the capture and the replay.

Show it to the end user and log it: it is the one key the support team needs.

A Phoenix controller handling both outcomes:

```elixir
defmodule MyAppWeb.SamlCallbackController do
  use MyAppWeb, :controller
  require Logger

  def callback(conn, %{"code" => code}) do
    case ExSaml.Assertion.get_from_code(code) do
      {:ok, {idp_id, attributes}} ->
        conn |> sign_in(idp_id, attributes) |> redirect(to: "/")

      {:error, %ExSaml.Error{reason: reason, trace_id: trace_id}}
      when reason in [:authorization_code_not_found, :assertion_not_found] ->
        Logger.warning("SAML code exchange failed", reason: reason, trace_id: trace_id)
        conn |> put_flash(:error, "Please sign in again") |> redirect(to: "/login")
    end
  end

  def callback(conn, %{"error_id" => error_id}) do
    case ExSaml.Error.get_from_id(error_id) do
      {:ok, %ExSaml.Error{trace_id: trace_id} = error} ->
        Logger.warning("SAML sign-in failed",
          trace_id: trace_id,
          reason: error.reason,
          scope: error.scope,
          step: error.step,
          idp_id: error.idp_id,
          saml_sub_status: error.saml_sub_status
        )

        conn
        |> put_flash(:error, "#{ExSaml.ErrorMessages.get(error)} (trace ID: #{trace_id})")
        |> redirect(to: "/login")

      {:error, %ExSaml.Error{reason: :error_not_found}} ->
        # expired or already consulted
        redirect(conn, to: "/login")
    end
  end

  def callback(conn, _params), do: redirect(conn, to: "/login")
end
```

## 2. `%ExSaml.Error{}` reference

| Field | Type | Meaning |
|---|---|---|
| `trace_id` | binary | The flow identifier (see above). `nil` only when an authorization code could not be found at all |
| `reason` | atom | What failed. Closed catalogue below; always an atom, so `case error.reason do … end` just works |
| `scope` | `:envelope \| :assertion \| nil` | For signature failures, which element failed |
| `step` | atom | Where the flow stopped: `:idp_lookup`, `:decode`, `:validate_authresp`, `:target_url`, `:code_exchange`, `:error_lookup`, `:replay`, `:unexpected` |
| `flow` | `:sp_initiated \| :idp_initiated \| nil` | Known once the assertion was decoded |
| `idp_id` | binary | The IdP the response was for |
| `relay_state` | binary | The `RelayState` received with the response |
| `saml_status` | atom | Top-level IdP `StatusCode` (`:responder`, `:requester`, `:version_mismatch`, `:unknown`) when `reason` is `:saml_error` |
| `saml_status_uri` | binary | The raw top-level status URI, kept even when it is not in the spec catalogue |
| `saml_sub_status` | atom | Nested IdP `StatusCode` (`:authn_failed`, `:invalid_nameid_policy`, …), see `ExSaml.Core.StatusCode` |
| `saml_message` | binary | The IdP `StatusMessage` text |
| `detail` | binary | Free text carried by the original error: exception message, decoding error, malformed status message, unknown term |
| `trace` | list | The `ExSaml.Debug.trace/1` of the flow when debug was on, else `nil` |
| `node` | atom | Node that produced the error |
| `at` | `DateTime` | When the error was produced |

`ExSaml.ErrorMessages.get/2` accepts the struct (or a bare reason, or any legacy
term) and returns a translated, user-facing message (`"en"` and `"fr"`). It
never raises: an unknown code yields the generic `unknown_error` message and a
warning log.

### Catalogue of reasons

Step `:idp_lookup`

| Reason | Extra fields | Meaning |
|---|---|---|
| `:unknown_idp` | `idp_id` | No identity provider is configured under that id |

Step `:decode` (payload and XML)

| Reason | Extra fields | Meaning |
|---|---|---|
| `:missing_saml_response` | | No `SAMLResponse` form field |
| `:invalid_response` | `detail` | Base64 / DEFLATE / XML parsing failed |
| `:bad_saml` | | No `Status` element |
| `:saml_error` | `saml_status`, `saml_status_uri`, `saml_sub_status`, `saml_message` | The IdP reported a non-success status. `saml_sub_status` is the actionable code: `:authn_failed`, `:request_denied`, `:invalid_nameid_policy`, `:unknown_principal`, `:no_passive`, … |
| `:bad_assertion` | | Not exactly one readable `Assertion` (missing, multiple, or decryption failed) |
| `:no_signature`, `:missing_certificate`, `:bad_digest`, `:bad_signature`, `:cert_not_accepted`, `:multiple_signatures`, `:insecure_algorithm`, `:unsupported_algorithm` | `scope` | Signature verification failed on the `Response` (`scope: :envelope`) or the `Assertion` (`scope: :assertion`) |
| `:bad_version` | | Not SAML 2.0 |
| `:bad_recipient` | | `SubjectConfirmationData/@Recipient` ≠ ACS URL |
| `:bad_audience` | | `AudienceRestriction` ≠ SP entity id |
| `:too_early` | | `NotBefore` in the future (5 s skew tolerated) |
| `:stale_assertion` | | `NotOnOrAfter` in the past |
| `:duplicate` | | Rejected by the configured duplicate-detection function |

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

Step `:code_exchange` (`ExSaml.Assertion.get_from_code/1`)

| Reason | Meaning |
|---|---|
| `:authorization_code_not_found` | The authorization code is unknown, expired (30 s) or was already used |
| `:assertion_not_found` | The code was valid but the assertion is gone from the assertion store |

Step `:error_lookup` (`ExSaml.Error.get_from_id/1`)

| Reason | Meaning |
|---|---|
| `:error_not_found` | The error id is unknown, expired (5 min) or was already consulted |

Step `:replay` (`ExSaml.Debug.replay/2`)

| Reason | Meaning |
|---|---|
| `:capture_not_found` | No capture for this trace (debug was off, or it expired) |
| `:payload_not_captured` | The capture holds no `SAMLResponse` (`capture: :none` was active) |
| `:unknown_idp` | The IdP of the capture is no longer configured |

Step `:unexpected`

| Reason | Extra fields | Meaning |
|---|---|---|
| `:exception` | `detail` | Something raised while consuming the response. The library fails closed with an `error_id` instead of a bare 500; the stack trace is in the server logs and, in debug mode, in the trace (`:unexpected_error` event) |

## 3. Legacy behaviour and upgrading to 2.0

### The session entry

The failure path still writes `{:error, %ExSaml.Error{}}` under the
`"ex_saml_error"` session key (without the `trace`, to stay cookie-friendly).
Do not rely on it for new code: the IdP POST is cross-site, so depending on
cookie settings the session written there may not be the one your callback
reads, and you end up with neither a `code` nor an error. `error_id` has no such
dependency.

### What changed in 2.0

Before 2.0 the library returned bare terms of several shapes:
`:bad_audience`, `{:envelope, {:error, :no_signature}}`,
`{:saml_error, status_uri_charlist, message}`, `{:invalid_response, "…"}`,
`{:error, :unauthorized}` and `{:error, assertion: :not_found}` from
`get_from_code/1`. They are all replaced by `{:error, %ExSaml.Error{}}`, and
**nothing they carried is lost**:

| Before | Now |
|---|---|
| `:bad_audience` | `%ExSaml.Error{reason: :bad_audience}` |
| `{:envelope, {:error, :no_signature}}` | `%ExSaml.Error{reason: :no_signature, scope: :envelope}` |
| `{:assertion, {:error, :bad_digest}}` | `%ExSaml.Error{reason: :bad_digest, scope: :assertion}` |
| `{:saml_error, uri, message}` | `%ExSaml.Error{reason: :saml_error, saml_status: :responder, saml_status_uri: "urn:…", saml_sub_status: :authn_failed, saml_message: "…"}` |
| `{:invalid_response, text}` | `%ExSaml.Error{reason: :invalid_response, detail: text}` |
| `{:unknown_idp, id}` | `%ExSaml.Error{reason: :unknown_idp, idp_id: id}` |
| `{:error, :unauthorized}` (`get_from_code/1`) | `%ExSaml.Error{reason: :authorization_code_not_found, step: :code_exchange}` |
| `{:error, assertion: :not_found}` (`get_from_code/1`) | `%ExSaml.Error{reason: :assertion_not_found, step: :code_exchange}` |

Migration steps:

1. Pattern-match on `%ExSaml.Error{reason: _}` instead of the tuples. If a
   fallback controller maps `{:error, :unauthorized}`, add a clause for
   `{:error, %ExSaml.Error{}}`.
2. Where you cannot migrate yet, `ExSaml.Error.to_legacy/1` rebuilds the old
   term from the struct.
3. `ExSaml.ErrorMessages.get/2` keeps accepting the old atoms and tuples, so
   message rendering needs no change.
4. Handle `?error_id=` in your callback (section 1). The session entry keeps
   working but now holds the struct.
5. The success map of `consume_signin_response/2` and the authorization code
   payload gain a `trace_id` (additive).

## 4. Debug mode

`ExSaml.Debug` records a **trace** of every decision point of the sign-in flow,
keeps a **capture** of failed flows (error summary + raw `SAMLResponse`), lists
them per IdP and can **replay** them. It is meant for production diagnostics.

### Enabling it at runtime

The flag lives in the cache configured with `config :ex_saml, cache:` (or a
dedicated `config :ex_saml, debug_cache:`). It is enabled **at runtime, without
a redeploy, a restart or a config change**, and it is visible to every node
sharing that cache:

```elixir
# From a remote console (`bin/my_app remote`) or an rpc:
#   bin/my_app rpc 'ExSaml.Debug.enable(idp_id: "acme", ttl: :timer.minutes(30))'

ExSaml.Debug.enable(ttl: :timer.minutes(30))                        # every IdP
ExSaml.Debug.enable(idp_id: "acme", ttl: :timer.minutes(30))        # one IdP only
ExSaml.Debug.enable(idp_id: "acme", capture: :always, log: :silent) # capture only, no logs
ExSaml.Debug.status()
#=> %{global: false, static: false, idps: ["acme"],
#     settings: %{{:idp, "acme"} => %{capture: :always, log: :silent}, global: nil},
#     expires_in_ms: %{{:idp, "acme"} => 1799812}}
ExSaml.Debug.disable("acme")
ExSaml.Debug.disable()
```

- Default: **off**.
- Scope: global, or a single `idp_id` (recommended in production; the IdP flag
  wins over the global one).
- **Auto-expiry**: the flag always expires, default 1 hour.
- Debug can never break a sign-in: every cache failure inside `ExSaml.Debug`
  degrades to "disabled".
- `config :ex_saml, debug: true` (or `[capture: …, log: …]`) is a static
  override for dev/test only. Without a configured cache, `enable/1` falls back
  to a node-local toggle with the same TTL.

### Options

| Option | Values | Default | Effect |
|---|---|---|---|
| `capture:` | `:on_error`, `:always`, `:none` | `:on_error` | When to keep the raw `SAMLResponse` (see "Captures") |
| `log:` | `:steps`, `:full`, `:silent` | `:steps` | `:steps` logs every event but **redacts** from the log message the payloads and assertions (PII) and the credentials — authorization code, nonces, user token — and **partially masks** NameIDs so a user stays recognisable (`jane@corp.com` → `j***@corp.com`, `employee-42` → `em***(11)`); nested values (`payload`, `value`, `relay_cache_entry`, …) follow the same rules. Everything stays intact in the trace. `:full` logs everything. `:silent` logs nothing and only feeds the trace and the capture |

Configuration keys:

| Key | Default | Meaning |
|---|---|---|
| `debug_cache:` | falls back to `cache:` | Cache used for flags, traces, captures and indexes. Use it to keep PII out of a shared cache |
| `debug_log_level:` | `:warning` | Logger level of the `[ExSaml.Debug]` lines |
| `trace_ttl:` | 15 min | TTL of a trace |
| `payload_ttl:` | 1 h | TTL of a promoted capture and of the per-IdP failure list |
| `provisional_ttl:` | 2 min | TTL of a capture written at receipt with `capture: :on_error`, before the flow is known to have failed |
| `max_failures_per_idp:` | 20 | Captures kept per IdP; older ones are evicted |

> **PII warning.** Traces and captures hold the raw `SAMLResponse`, the NameID
> and the assertion attributes in the cache; `log: :full` also writes them to
> the logs. Keep the TTL short, scope to one IdP, and prefer a dedicated
> `debug_cache:` in production.

### Traces

Each event is logged as `[ExSaml.Debug] <event> %{…}` and appended to the flow
trace, readable with `ExSaml.Debug.trace(trace_id)` and embedded in
`%ExSaml.Error{trace: _}`.

| Event | Where | Recorded |
|---|---|---|
| `:authn_request` | AuthnRequest sent | idp_id, relay_state, target_url, nonce and its source (`:assigns` / `:cookie` / `:generated`), binding, IdP URL, whether a session id / user token was present |
| `:response_received` | ACS entry | relay_state (raw / decoded), relay-state cache hit and content, method, host, origin / referer / user-agent, cookie names, body param keys, `SAMLEncoding`, size of the `SAMLResponse` (the payload itself lives only in the capture), which session keys were present |
| `:saml_status_error` | IdP non-success status | top-level and nested `StatusCode`, `StatusMessage`, `StatusDetail` |
| `:validate_assertion_failed` | XML validation | the reason, and for `:bad_assertion` which extraction path failed (`where:`) with the swallowed exception |
| `:decode_payload_failed` | payload decoding | encoding, payload size, exception with stack trace |
| `:decode_result` | after decoding | the full decoded assertion, or the reason |
| `:validate_authresp_result` | flow validation | result, and the **provenance** (`:session` / `:cache` / `:none`) of the expected relay_state, idp_id and nonce |
| `:code_issued` | success | code, assertion key, nonce, flow, target URL and its source |
| `:code_stored` / `:code_taken` | `ExSaml.AuthorizationCodeCache` | code, hit / miss, value, remaining TTL. This is where a double use of the code shows up |
| `:code_exchanged` | `ExSaml.Assertion.get_from_code/1` | code found?, assertion found?, assertion |
| `:relay_state_taken` / `:relay_state_deleted` | `ExSaml.RelayStateCache` | key, hit / miss |
| `:error_issued` | failure | trace_id, reason, scope, step, detail, target URL and its source, session snapshot |
| `:unexpected_error` | rescued exception | formatted exception with its stack trace |
| `:logout_response_failed` / `:logout_request_failed` | single logout | error, size of the payload, session snapshot |

### Captures

A capture is the diagnostic record of a **failed** flow: a summary of the error
and the raw `SAMLResponse`, kept together under the `trace_id`.

| Key | Content |
|---|---|
| `trace_id`, `idp_id`, `received_at` | identity of the flow |
| `captured_on` | why it was kept: `:error` (the library rejected the response), `:authorization_code_not_found` (the code was never exchanged, or exchanged twice), `:assertion_not_found`, or `:always` |
| `error` | `%{trace_id, reason, scope, step, idp_id}` — no PII |
| `saml_response` | the base64 exactly as posted by the IdP (`nil` with `capture: :none`) |
| `saml_encoding`, `relay_state`, `consume_uri`, `entity_id` | what a faithful replay needs |

How it is written, per `capture:` mode:

- `:on_error` (default): written at receipt with `provisional_ttl` (2 min),
  never deleted explicitly, and **promoted** — full `payload_ttl`, error
  summary, added to the IdP's failure list — when the flow fails: in the
  library (`:error`), or later when the authorization code cannot be exchanged
  (`:authorization_code_not_found`, `:assertion_not_found`). A successful flow
  simply lets its provisional capture expire. This is what makes the
  "signed in on the library side, failed on the consumer side" case
  diagnosable.
- `:always`: written at receipt with `payload_ttl`, promoted on failure.
- `:none`: nothing at receipt; a failure still leaves a capture, without the
  payload.

Reading:

```elixir
ExSaml.Debug.failures("acme")
#=> [%{trace_id: "…", received_at: ~U[…], captured_on: :authorization_code_not_found,
#      error: %{reason: :authorization_code_not_found, step: :code_exchange, …}}, …]

ExSaml.Debug.failure(trace_id)               # the full capture, or nil
ExSaml.Debug.saml_response(trace_id)         # the base64
ExSaml.Debug.saml_response(trace_id, decode: true) # the XML document
ExSaml.Debug.capture(trace_id)               # also returns pending / :always captures
```

### Replay

`ExSaml.Debug.replay(trace_id)` runs the captured `SAMLResponse` through the
same decoding and validation as the live flow, against the **current**
configuration of its IdP, using the `consume_uri` and `entity_id` captured at
receipt. Time conditions (`NotBefore`, `NotOnOrAfter`) are evaluated **as of
the instant the response was received** (`now: received_at`), so a capture
replayed hours later does not fail on `:stale_assertion` for the wrong reason;
pass `now:` to evaluate at another instant.

```elixir
ExSaml.Debug.replay(trace_id)
#=> {:error, %ExSaml.Error{reason: :cert_not_accepted, scope: :assertion, step: :decode}}

# after updating the IdP metadata:
ExSaml.Debug.replay(trace_id)
#=> {:ok, %ExSaml.Core.Assertion{}}
```

Signatures are checked against the current IdP metadata: a rotated certificate
shows up as `:cert_not_accepted`, which is itself the diagnosis. Replay never
emits an authorization code or touches any session.

## 5. Troubleshooting recipes

**"Authorization code not found"** (`get_from_code/1` →
`%ExSaml.Error{reason: :authorization_code_not_found}`, or your own
`AuthorizationCodeCache.take/1` returns `nil`)

Enable debug for the IdP, reproduce, then look at `ExSaml.Debug.failures(idp_id)`:
the flow is listed with `captured_on: :authorization_code_not_found` and its
capture holds the `SAMLResponse`. Then read the trace:

- two `:code_taken` events for the same code, the second with `hit: false` →
  the callback URL was requested twice (browser prefetch, link scanner, refresh,
  double submit). The first request did sign the user in.
- `:code_stored` present, single `:code_taken` with `hit: false` and a
  `remaining_ttl` of `nil` → the code expired (30 s) or was written on a node
  whose cache is not shared with the node serving the callback.
- no `:code_stored` at all → the IdP response never reached `:code_issued`;
  look for `:error_issued` instead and handle `error_id` in your callback.

**"error_id but the session is empty"**

Expected: the failure path no longer needs the session. Read
`%ExSaml.Error{}`; `trace[:response_received].session` shows what the ACS
request could see, and `relay_cache_hit` whether the server-side relay state
was still there.

**`:invalid_relay_state`**

`:validate_authresp_result` shows `relay_state_expected` and its source. `:none`
means neither the session nor the relay-state cache had it: the AuthnRequest is
older than 5 minutes, or it was issued on a node that does not share the cache.

**`:bad_assertion`**

`:validate_assertion_failed` carries `where:` — `:assertion_count` (0 or several
`Assertion` elements), `:decrypted_assertion_count`, or `:decrypt_assertion`
with the exception (wrong SP key, unsupported cipher). `replay/2` confirms
whether a configuration change fixes it.

**`:saml_error` from the IdP**

`saml_sub_status` is the code to act on: `:authn_failed` (user could not
authenticate), `:request_denied` (user not entitled to the app),
`:invalid_nameid_policy` (NameID format mismatch), `:unknown_principal`,
`:no_passive`. `saml_message` carries the IdP's own explanation when it sent one.

**Signature failures** (`scope: :envelope` or `:assertion`)

`:missing_certificate` means the IdP signs without embedding its X.509
certificate; `:cert_not_accepted` means it embeds one that is not in the IdP
metadata (rotated certificate); `:bad_signature` means the document was
altered or signed with another key; `:insecure_algorithm` means RSA-SHA1. Update
the metadata, then `replay/2` the capture to confirm before asking the user to
try again.
