# Proposal — REST API over the ex_saml debug and error tooling

Status: **proposal**, not implemented. Companion to `guides/error_handling_and_debugging.md`.
Everything below maps one-to-one onto functions that already exist in the library
(`ExSaml.Debug`, `ExSaml.Error`, `ExSaml.ErrorMessages` for the per-failure message);
the API adds transport, serialisation and access control, nothing else.

## 1. Goals and non-goals

Goals

- Let support and on-call engineers diagnose a failed SAML sign-in **without a remote console**:
  turn debug on for one IdP, list its recent failures, read a trace, download the captured
  `SAMLResponse`, replay it, turn debug off.
- Keep the library's safety properties: everything expires, debug never affects the auth flow,
  PII is redacted unless explicitly asked for.
- Be trivially mountable in any Plug/Phoenix app that already uses ex_saml.

Non-goals

- Authentication and authorisation. The router is shipped **unauthenticated by design** and must
  be mounted behind the consumer's admin pipeline (see §6). It must never be reachable from the
  public internet.
- Durable storage. The API reads what the cache holds; retention is the cache's TTLs (#59 covers
  a pluggable sink).
- Consuming an `error_id` on behalf of the end user (`ExSaml.Error.get_from_id/1` is single-use
  and belongs to the callback, not to an admin API).

## 2. Shape

A `Plug.Router` provided by the library, `ExSaml.DebugRouter`, mounted by the consumer:

```elixir
# Phoenix
scope "/admin/saml", as: :saml_admin do
  pipe_through [:browser_or_api, :require_admin, :audit]
  forward "/", ExSaml.DebugRouter
end

# Plain Plug
forward "/admin/saml", to: ExSaml.DebugRouter
```

Conventions

- JSON in and out, `application/json; charset=utf-8`.
- Times are ISO 8601 UTC strings; durations are milliseconds.
- Atoms are serialised as strings without the colon (`"bad_digest"`), and parsed back only
  against closed catalogues (never `String.to_atom/1`).
- Errors use one envelope:

```json
{ "error": { "code": "capture_not_found", "message": "No capture exists for this trace …", "trace_id": "…" } }
```

  with HTTP status 404 for `*_not_found`, 400 for invalid parameters, 409 for a refused state
  change, 500 never (the library functions do not raise; a raise here is a bug).

## 3. Resources

### 3.1 Debug switch

| Method | Path | Maps to | Notes |
|---|---|---|---|
| `GET` | `/debug` | `ExSaml.Debug.status/0` | global / per-IdP flags, settings, remaining TTLs |
| `PUT` | `/debug` | `ExSaml.Debug.enable/1` | global scope |
| `PUT` | `/debug/idps/:idp_id` | `ExSaml.Debug.enable(idp_id: …)` | per-IdP scope (recommended) |
| `DELETE` | `/debug` | `ExSaml.Debug.disable/0` | |
| `DELETE` | `/debug/idps/:idp_id` | `ExSaml.Debug.disable/1` | |

`PUT` body (all optional):

```json
{ "ttl_ms": 1800000, "capture": "on_error", "log": "steps" }
```

`capture` ∈ `none | on_error | always`, `log` ∈ `steps | full | silent`. Validation errors → 400.
`ttl_ms` is capped by the server (`max_debug_ttl_ms`, default 4 h) → 400 above the cap.

`GET /debug` response:

```json
{
  "global": false,
  "static": false,
  "idps": ["acme"],
  "settings": { "global": null, "acme": { "capture": "on_error", "log": "steps" } },
  "expires_in_ms": { "acme": 1799812 },
  "config": {
    "trace_ttl_ms": 900000, "payload_ttl_ms": 3600000, "provisional_ttl_ms": 300000,
    "max_failures_per_idp": 20, "error_ttl_ms": 300000,
    "enforced_response_checks": ["bad_issuer", "bad_in_response_to", "session_expired", "bad_subject_confirmation"]
  }
}
```

### 3.2 Failures

| Method | Path | Maps to | Notes |
|---|---|---|---|
| `GET` | `/idps/:idp_id/failures` | `ExSaml.Debug.failures/1` | most recent first, ≤ `max_failures_per_idp` |
| `GET` | `/failures/:trace_id` | `ExSaml.Debug.failure/1` | the capture **without** the payload by default |
| `GET` | `/failures/:trace_id/saml_response` | `ExSaml.Debug.saml_response/2` | see formats below |
| `POST` | `/failures/:trace_id/replay` | `ExSaml.Debug.replay/2` | body `{ "now": "2026-09-03T12:14:03Z" }` optional |

`GET /idps/acme/failures`:

```json
{
  "idp_id": "acme",
  "failures": [
    { "trace_id": "62X06…", "received_at": "2026-09-03T12:14:03Z", "captured_on": "error",
      "error": { "reason": "bad_digest", "scope": "assertion", "step": "decode" } },
    { "trace_id": "k9Pq…", "received_at": "2026-09-03T12:02:41Z", "captured_on": "authorization_code_not_found",
      "error": { "reason": "authorization_code_not_found", "scope": null, "step": "code_exchange" } }
  ]
}
```

`GET /failures/:trace_id`:

```json
{
  "trace_id": "62X06…", "idp_id": "acme", "received_at": "…", "captured_on": "error",
  "error": { "reason": "bad_digest", "scope": "assertion", "step": "decode", "idp_id": "acme" },
  "relay_state": "…", "saml_encoding": null,
  "consume_uri": "https://sp.example.com/sso/consume/acme",
  "entity_id": "https://sp.example.com/sso/metadata/acme",
  "saml_response": { "present": true, "bytes": 6120, "href": "/failures/62X06…/saml_response" },
  "message": "Please make sure that you selected the correct Signature Algorithm (SHA-256)"
}
```

`message` is the user-facing text from `ExSaml.ErrorMessages.get/2` in the locale given by
`?locale=` (default `en`).

`GET /failures/:trace_id/saml_response` content negotiation:

| `Accept` / `?format=` | Returns |
|---|---|
| `application/json` / `format=json` (default) | `{ "trace_id": "…", "saml_encoding": null, "base64": "PHNhbWxwOl…" }` — the base64 exactly as posted, with what is needed to decode it |
| `application/xml` / `format=xml` | the decoded document, `Content-Disposition: attachment; filename="saml-response-<trace_id>.xml"` |

`?format=` wins over `Accept` when both are given; any other value → 400.

Downloading the payload is the one operation that hands PII to a human on purpose: it is
**audited** (see §6) and returns 404 `payload_not_captured` when `capture: :none` was active.

`POST /failures/:trace_id/replay` → 200:

```json
{ "trace_id": "…", "evaluated_at": "2026-09-03T12:14:03Z", "result": "error",
  "error": { "reason": "cert_not_accepted", "scope": "assertion", "step": "decode" } }
```

or, once the IdP metadata is fixed:

```json
{ "trace_id": "…", "evaluated_at": "…", "result": "ok",
  "assertion": { "issuer": "https://idp.example.com", "subject": "j***@corp.com", "attributes": ["email", "groups"] } }
```

On success the assertion is summarised, never returned whole: subject masked like the logs,
attribute **names** only.

### 3.3 Traces

| Method | Path | Maps to |
|---|---|---|
| `GET` | `/traces/:trace_id` | `ExSaml.Debug.trace/1` |

```json
{
  "trace_id": "62X06…",
  "events": [
    { "event": "authn_request", "at": "…", "node": "app@10.0.0.7",
      "data": { "nonce_source": "cookie", "binding": "http_redirect", "authn_request_id": "_a1…" } },
    { "event": "response_received", "at": "…", "node": "…",
      "data": { "relay_cache_hit": true, "session": { "relay_state": null }, "saml_response_bytes": 6120 } },
    { "event": "validation_check", "at": "…", "node": "…",
      "data": { "check": "bad_issuer", "enforced": false, "expected": "…", "actual": "…" } },
    { "event": "decode_result", "at": "…", "node": "…", "data": { "result": "error", "reason": "bad_digest", "scope": "assertion" } }
  ]
}
```

Query parameters: `?redact=false` returns the unredacted event data (default applies the same
rules as `log: :steps`: payloads and assertions dropped, credentials removed, NameIDs masked).
Unredacted access is audited.

### 3.4 Validation policy (optional, second step)

| Method | Path | Maps to |
|---|---|---|
| `GET` | `/validation` | `ExSaml.Core.ValidationContext.enforced_checks/0`, `all_checks/0` |

Read-only: the response lists the enforced checks and the available ones. Changing the policy at
runtime is out of scope until the enforcement flag is cluster-wide (cache-backed like the debug
switch), the second half of #55.

## 4. Serialisation rules

Traces and captures hold Elixir terms that JSON cannot carry. One serialiser,
`ExSaml.Debug.JSON` (to be added), applied to every response:

| Term | JSON |
|---|---|
| atom | string, no colon (`nil` → `null`, booleans as is) |
| `DateTime` / `NaiveDateTime` | ISO 8601 string |
| tuple | array |
| keyword list | object |
| charlist | string when printable, else array of integers |
| binary that is not valid UTF-8 | `{ "base64": "…" }` |
| xmerl record / struct with no JSON meaning | `{ "inspect": "…" }` truncated to 1 KB |
| map with atom keys | object with string keys |

Redaction (default on for traces) reuses `ExSaml.Debug.redact/1`, so the API and the logs mask
the same things the same way.

## 5. Behaviour and limits

- **Read paths never write**, except `POST …/replay`, which is side-effect free on the auth flow
  (no code issued, no session touched) but does log through `ExSaml.Debug` if debug is on.
- **Zero cost when off** is preserved: the router only calls into the same memoised checks.
- **Size**: a trace is capped by `trace_ttl` and the flow, a capture by the IdP's response size;
  no pagination needed at 20 failures per IdP.
- **Cluster**: all reads hit the shared cache, so any node answers for any flow. The
  `node` field in events says where the flow ran.

## 6. Security requirements for the consumer

The router is a diagnostic surface over authentication data. Mounting it implies:

1. **Authentication + authorisation** in the pipeline in front of it (admin role). The router
   logs a warning at startup when it is mounted at the root path, as a reminder; that is not a
   protection.
2. **Network exposure**: internal network, VPN or admin host only; never the public ACS host.
   Rate limiting, like authentication, belongs to the consumer's pipeline (the platform already
   has its own rate-limiting library); the router does not implement one.
3. **Audit log**: the router emits `[ExSaml.DebugRouter] <method> <path> actor=<…> trace_id=<…>`
   for every request, and marks `pii=true` on payload downloads and unredacted traces. The
   consumer sets the actor via `conn.assigns[:ex_saml_actor]`
   (or a configured function); a missing actor is logged as `"unknown"` and returns 403 when
   `require_actor: true` (default).
4. **TTL cap** on `PUT /debug` (`max_debug_ttl_ms`), so nobody leaves debug on for a week.
5. **CSRF**: state-changing routes accept JSON only (`Content-Type: application/json`), which
   defeats simple form-based CSRF; consumers with cookie sessions should still put their CSRF
   plug in the pipeline.

## 7. Worked examples

Support gets "I can't log in, error ID 62X06lq6…" from a user of `acme`:

```sh
BASE=https://admin.internal/admin/saml

# 1. what happened
curl -s $BASE/failures/62X06lq6SrHviyyxGCnCasg_NKdMtQuh | jq '.error, .message.fr'
#=> { "reason": "cert_not_accepted", "scope": "assertion", "step": "decode", "idp_id": "acme" }
#=> "Le certificat utilisé pour signer la réponse SAML ne correspond pas aux métadonnées de l'IdP…"

# 2. confirm on the trace that the rest of the flow was fine
curl -s $BASE/traces/62X06lq6SrHviyyxGCnCasg_NKdMtQuh | jq '[.events[].event]'
#=> ["authn_request","response_received","validate_assertion_failed","decode_result","error_issued"]

# 3. after the IdP metadata has been refreshed, prove the fix without asking the user
curl -s -X POST $BASE/failures/62X06lq6SrHviyyxGCnCasg_NKdMtQuh/replay | jq .result
#=> "ok"
```

On-call sees a spike of `missing_assertion_key` for `acme` and no error id:

```sh
# turn debug on for that IdP only, 30 min, capture every response, no log noise
curl -s -X PUT $BASE/debug/idps/acme -H 'content-type: application/json' \
     -d '{"ttl_ms":1800000,"capture":"always","log":"silent"}'

# a few minutes later
curl -s $BASE/idps/acme/failures | jq '.failures[] | {trace_id, captured_on, reason: .error.reason}'
#=> { "trace_id": "k9Pq…", "captured_on": "authorization_code_not_found", "reason": "authorization_code_not_found" }

curl -s $BASE/traces/k9Pq… | jq '[.events[] | select(.event=="code_taken") | .data.hit]'
#=> [true, false]            # the callback URL was requested twice: prefetch or double submit

curl -s -X DELETE $BASE/debug/idps/acme
```

Handing a bad response to the IdP vendor:

```sh
curl -s -H 'accept: application/xml' $BASE/failures/k9Pq…/saml_response -o saml-response-k9Pq.xml
```

## 8. Implementation sketch

- `lib/ex_saml/debug/router.ex` — `Plug.Router`, ~200 lines, JSON via `Jason` if present else
  `:json` (OTP 27+); no new mandatory dependency.
- `lib/ex_saml/debug/json.ex` — the serialiser of §4 (~80 lines) plus tests on a real trace.
- `lib/ex_saml/debug/audit.ex` — one function, one log line per request.
- Config: `debug_api: [max_debug_ttl_ms: …, require_actor: true, actor: {Mod, :fun}]`.
- Tests with `Plug.Test` against `ExSaml.StubCache`: every route, both redaction modes, the 404
  and 400 envelopes, the TTL cap, the actor requirement, the audit lines.
- Guide: a "Debug API" section; README: one paragraph and the mount snippet.

Estimated size: one PR, ~600 lines including tests, no change to the existing debug functions.

## 9. Open questions

- Should `GET /failures/:trace_id` also expose the **peek** of an unconsumed error entry
  (`ErrorCache.get/1`) for support, without consuming it? Useful, but it duplicates the capture's
  `error` summary; proposal: no, the capture is the support record.
- Cluster-wide enforcement toggle (§3.4) — wait for the second half of #55.
- Should the router offer a **live tail** (SSE) of `[ExSaml.Debug]` events for one IdP? Attractive
  for on-call, but it means a Logger backend or a PubSub hook; out of scope for a first version.
