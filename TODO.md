# TODO

## Cache Layer

### Done

- [x] Add `take/1` to `AssertionCache` — delegates to cache backend's `take/1`
- [x] Create `AuthorizationCodeCache` module with `ttl/0`, `get/1`, `put/1-2`, `take/1`, `put_new!/2`
- [x] `RelayStateCache.take/1` — already existed

---

## Security Fixes (from SECURITY_REVIEW.md)

### P0 — Critical

- [ ] **XXE (CVE-2026-28809):** Add `allow_entities: false` to all `:xmerl_scan.string/2` calls
  - `lib/ex_saml/core/binding.ex:44` — decode_response DEFLATE path
  - `lib/ex_saml/core/binding.ex:60` — decode_response fallback path
  - `lib/ex_saml/core/sp.ex:518` — decrypt_assertion

- [ ] **XSW (Signature Wrapping):** Reject responses containing multiple assertions. Verify
  that the extracted assertion element matches the signed element by ID.
  - `lib/ex_saml/core/sp.ex` — `extract_assertion/3`

- [ ] **NotBefore validation:** Add time lower bound check in assertion validation.
  Current code only checks NotOnOrAfter (upper bound).
  - `lib/ex_saml/core/saml.ex` — add `validate_not_before/1`

### P1 — High

- [ ] **Optional signatures warning:** Log a warning when `idp_signs_envelopes` or
  `idp_signs_assertions` is set to `false`. Consider requiring at least one.
  - `lib/ex_saml/core/sp.ex` — `verify_envelope_signature/2`, `verify_assertion_signature/2`

- [ ] **Certificate validation:** Require fingerprint validation (never use `:any` in
  production). Add certificate expiry check.
  - `lib/ex_saml/core/xml/dsig.ex` — `check_fingerprints/2`

- [ ] **Algorithm whitelist:** Return `{:error, :unsupported_algorithm}` for unknown
  signature algorithms instead of crashing.
  - `lib/ex_saml/core/xml/dsig.ex` — `verify/2`

- [ ] **Replay detection:** Use `check_dupe_ets/2` as the default duplicate detection
  function instead of a no-op.
  - `lib/ex_saml/core/sp.ex` — `validate_assertion/2`

### P2 — Medium / Low

- [ ] **Comment injection:** Strip XML comments and normalize whitespace in extracted
  NameID and attribute values.
  - `lib/ex_saml/core/saml.ex` — `decode_assertion_subject/1`

- [ ] **PKCS#7 padding:** Implement proper PKCS#7 padding validation instead of dropping
  all trailing bytes < 16.
  - `lib/ex_saml/core/sp.ex` — `strip_pkcs7_padding/1`

### Done

- [x] **SHA-1 rejection:** RSA-SHA1 signatures are now rejected on verification with
  `{:error, :insecure_algorithm}` and an error log.

---

## Previous Audit Items

### Audit the SAML nonce (`auth_handler.ex`)

**Previous location:** `ExSaml.AuthHandler.request_idp/2` (line ~43)

**Context:** The nonce is read from an encrypted cookie (`saml_nonce`) or falls back
to `UUID.uuid4()`. It is stored in the `RelayStateCache` alongside the relay state
and later retrieved during `validate_authresp` in `SPHandler`.

**What to audit:**
- Verify that the nonce actually prevents replay attacks (is it checked once and
  discarded?).
- Confirm the encrypted cookie cannot be forged or reused across sessions.
- Ensure the `UUID.uuid4()` fallback is acceptable — it is random but not
  cryptographically tied to the session.

### Session elements have no TTL (`auth_handler.ex`)

**Previous location:** `ExSaml.AuthHandler.request_idp/2` (line ~63)

**Context:** `put_session("relay_state", ...)` and `put_session("idp_id", ...)` are
written to the Plug session without an explicit expiration. The relay state *cache*
entry has a 5-minute TTL, but the session keys themselves persist until the session
expires or is dropped.

**What to do:**
- Evaluate whether stale session keys could cause issues (e.g., a user who never
  completes the SSO flow retains the relay state in their session indefinitely).
- Consider clearing these keys after a successful or failed authentication, or
  enforcing a session-level TTL.
