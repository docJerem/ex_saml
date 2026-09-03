# The debug API

`ExSaml.Debug` records everything needed to explain a failed sign-in, but from
the outside it is a console API: `bin/my_app rpc 'ExSaml.Debug.failures("acme")'`.
`ExSaml.DebugRouter` is the same functions over HTTP, so support and on-call can
diagnose a customer's SAML problem without a remote shell.

It adds transport, serialisation and access control. It does not add storage:
what you can read is what the cache still holds, bounded by the TTLs in
[Debug mode](error_handling_and_debugging.md#4-debug-mode).

## Mounting it

```elixir
# Phoenix
scope "/admin/saml" do
  pipe_through [:api, :require_admin, :audit]

  forward "/", ExSaml.DebugRouter,
    authorize: {MyApp.Saml.Debug, :authorize},
    actor: {MyApp.Saml.Debug, :actor}
end

# Plain Plug
forward "/admin/saml",
  to: ExSaml.DebugRouter,
  init_opts: [authorize: {MyApp.Saml.Debug, :authorize}]
```

The router performs **no authentication**. It reads authentication data, so it
must sit behind your own admin pipeline, on an internal network, and never on
the public ACS host. Rate limiting belongs to that pipeline too.

Because it cannot check that for you, it does the one thing it can: it refuses
to start without an explicit `:authorize` decision.

```elixir
defmodule MyApp.Saml.Debug do
  # {:ok, :all} | {:ok, [idp_id]} | {:error, reason}
  def authorize(conn) do
    case conn.assigns[:current_admin] do
      nil -> {:error, :unauthenticated}
      %{role: :support} -> {:ok, :all}
      %{organization: org} -> {:ok, MyApp.SSO.idp_ids(org)}
    end
  end

  def actor(conn), do: conn.assigns[:current_admin].email
end
```

`{:ok, [idp_id]}` is the interesting one: it scopes every route to that set, so
the same mount can serve a multi-tenant admin UI. Pass `authorize: :none` to
state deliberately that the pipeline in front is the only control.

## Options

| Option | Default | |
|---|---|---|
| `:authorize` | **required** | `{Mod, :fun}`, a 1-arity function, or `:none` |
| `:actor` | `conn.assigns[:ex_saml_actor]` | who to name in the audit line |
| `:require_actor` | `true` | refuse when no actor can be resolved |
| `:allow_global_scope` | `false` | permit the global switch |
| `:allow_unredacted` | `false` | permit `?redact=false` on a trace |
| `:allow_payload_download` | `true` | permit reading a captured `SAMLResponse` |
| `:allow_node_local` | `false` | permit writes with no cache configured |
| `:max_debug_ttl_ms` | 4 h | cap on `ttl_ms` |
| `:default_locale` | `"en"` | for `GET /failures/:trace_id` |
| `:audit_level` | `:info` | |
| `:audit_sink` | `nil` | `{Mod, :fun}` called with the audit entry |

The same options may be set under `config :ex_saml, debug_api: [...]`; mount
options win. Both Plug's and Phoenix's `forward` call `init/1` at compile time,
so `{Mod, :fun}` tuples work everywhere while anonymous functions need
`init_mode: :runtime`.

## Routes

| | | |
|---|---|---|
| `GET` | `/debug` | activation state, retention config, whether a cache is configured |
| `PUT` | `/debug` | enable globally |
| `DELETE` | `/debug` | disable globally |
| `PUT` | `/debug/idps/:idp_id` | enable for one IdP |
| `DELETE` | `/debug/idps/:idp_id` | disable for one IdP |
| `GET` | `/idps/:idp_id/failures` | recent failures, most recent first |
| `GET` | `/failures/:trace_id` | one capture, without the payload |
| `GET` | `/failures/:trace_id/saml_response` | the payload, `?format=json` or `xml` |
| `POST` | `/failures/:trace_id/replay` | re-run it against the live configuration |
| `GET` | `/traces/:trace_id` | the flow's events |
| `GET` | `/validation` | the response-validation policy |

`PUT` takes `{"ttl_ms": 1800000, "capture": "always", "log": "steps"}`, all
optional. `capture` and `log` are parsed against closed catalogues.

## A support session

```sh
BASE=https://admin.internal/admin/saml
AUTH='authorization: Bearer …'

# "I can't log in, error ID 62X06lq6…"
curl -s -H "$AUTH" $BASE/failures/62X06lq6 | jq '.error, .message'
#=> { "reason": "cert_not_accepted", "scope": "assertion", "step": "decode" }
#=> "The certificate used to sign the SAML response does not match the IdP metadata…"

# Was the rest of the flow fine?
curl -s -H "$AUTH" $BASE/traces/62X06lq6 | jq '[.events[].event]'
#=> ["authn_request","response_received","validate_assertion_failed","decode_result"]

# The IdP metadata has been refreshed. Is it fixed, without asking the user to retry?
curl -s -X POST -H "$AUTH" $BASE/failures/62X06lq6/replay | jq .result
#=> "ok"
```

A spike of failures with no error id to go on:

```sh
curl -s -X PUT -H "$AUTH" -H 'content-type: application/json' \
     -d '{"ttl_ms":1800000,"capture":"always","log":"silent"}' $BASE/debug/idps/acme

# a few minutes later
curl -s -H "$AUTH" $BASE/idps/acme/failures |
  jq '.failures[] | {trace_id, captured_on, reason: .error.reason}'

curl -s -X DELETE -H "$AUTH" $BASE/debug/idps/acme
```

Handing a bad response to the IdP vendor:

```sh
curl -s -H "$AUTH" -H 'accept: application/xml' \
     $BASE/failures/k9Pq/saml_response -o saml-response-k9Pq.xml
```

## Answers that are easy to misread

**A replay that still fails is a 200.** `{"result": "error"}` means the replay
ran and the response is still rejected — the ordinary answer to "is it fixed
yet?". Only 4xx means the replay could not be attempted at all
(`capture_not_found`, `payload_not_captured`, `unknown_idp`).

**A `trace_id` you may not see is a 404, not a 403.** Indistinguishable from one
that expired, deliberately: trace ids travel — they are the `?error_id=` a user
pastes into a support ticket — so a distinguishable 403 would confirm the
existence of another tenant's flow to anyone holding an id. An `idp_id` outside
your set *is* a 403, since that only says the id is not in your own list.

**An empty `failures` list may mean the cache is missing.** `GET /debug` reports
`"cache": {"configured": false}` and every response carries
`x-ex-saml-cache: none` when `config :ex_saml, :cache` (or `:debug_cache`) is
unset. Writes are refused with 409 `cache_not_configured` in that state, because
`enable/1` would otherwise arm a single node behind your load balancer.

**404 and 409 on a payload are different problems.** `payload_not_captured`
means the flow was recorded with `capture: :none`; `payload_not_decodable` means
the bytes are there but do not inflate or decode to text — fetch them with
`?format=json` and hand the base64 to the IdP vendor.

## What it hands over

Everything is redacted by default, with the same rules as the `log: :steps`
lines: payloads and assertions dropped, credentials removed, NameIDs masked.
Two routes deliberately hand over more, and both are marked `pii=true` in the
audit line:

- **the payload** — the IdP's own signed document, containing the end user's
  attributes. This is the point of the tool, so it is on by default
  (`:allow_payload_download`).
- **an unredacted trace** (`?redact=false`) — which contains the authorization
  code, a *live bearer credential* exchangeable for the assertion until it
  expires, plus the session nonces. A different risk class, so it has its own
  opt-in and is off by default (`:allow_unredacted`).

A successful replay is summarised, never returned whole: the subject is masked
the way the logs mask it, and only attribute *names* are listed.

## Auditing

One line per request, before the response is sent, so refusals are recorded too:

```
[ExSaml.DebugRouter] GET /failures/62X06lq6/saml_response actor=jane@corp.com trace_id=62X06lq6 status=200 pii=true
```

A missing actor is `unknown`, and is refused outright unless
`require_actor: false`. An unhandled error is logged at `:error` and re-raised
for your own reporter rather than producing an audit line. Set `:audit_sink` to `{Mod, :fun}` to also receive the
entry as a map; a sink that raises is logged and ignored rather than failing the
request.

## JSON

No JSON library is required. The encoder is part of the library, and decoding
request bodies uses Jason if you have it, OTP 27's `:json` otherwise. Under
Phoenix the decoder never runs at all, since `Plug.Parsers` has already read the
body. If neither is available and you mount under plain Plug, set:

```elixir
config :ex_saml, debug_api: [json_decoder: {MyApp.JSON, :decode}]
```
