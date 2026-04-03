# ExSaml Security Review

## 1. CVE-2026-28809 — XML External Entity (XXE) in esaml

### Description

**CVE-2026-28809** is an XXE vulnerability affecting the Erlang `esaml` library and all forks.
Published March 23, 2026 by the Erlang Ecosystem Foundation (EEF) CNA.

- **CWE:** CWE-611 — Improper Restriction of XML External Entity Reference
- **CVSS 4.0:** 6.3 (MEDIUM)
- **Advisory:** GHSA-4g2h-vm7x-747c
- **Affected:** `pkg:hex/esaml`, all forks (arekinath, handnot2, dropbox)

### Root Cause

On Erlang/OTP < 27, `:xmerl_scan` defaults to `allow_entities: true`. An attacker sends a
crafted SAML message containing an XML External Entity declaration. The SAML endpoint parses
this **before** signature verification, allowing:

- **Local file read** (`file:///etc/passwd`, Kubernetes secrets, etc.)
- **SSRF** via internal network URLs
- **Information leakage** through error messages or logs

### Our Exposure

Three call sites in ExSaml.Core use `:xmerl_scan.string/2` without `allow_entities: false`:

| File | Line | Context |
|------|------|---------|
| `lib/ex_saml/core/binding.ex` | 44 | `decode_response/2` — DEFLATE path |
| `lib/ex_saml/core/binding.ex` | 60 | `decode_response/2` — fallback path |
| `lib/ex_saml/core/sp.ex` | 518 | `decrypt_assertion/2` — after decryption |

### Fix

Add `allow_entities: false` to all `:xmerl_scan.string/2` calls:

```elixir
:xmerl_scan.string(xml_data, namespace_conformant: true, allow_entities: false)
```

OTP 27+ defaults to `false`, but we should be explicit for backwards compatibility.

---

## 2. Full Security Review

### CRITICAL

#### 2.1 XML Signature Wrapping (XSW) — Multiple Assertion Attack

**File:** `lib/ex_saml/core/sp.ex` — `extract_assertion/3`

The code extracts the **first** `<saml:Assertion>` element via XPath, then verifies the
signature separately. An attacker can structure XML so that:

1. A valid signed assertion exists at one position
2. A malicious unsigned assertion is at the position extracted by XPath

```elixir
# extract_assertion only takes the first match
case :xmerl_xpath.string(~c"/samlp:Response/saml:Assertion", xml, [{:namespace, ns}]) do
  [a] when Record.is_record(a, :xmlElement) -> {:ok, a}
  _ -> {:error, :bad_assertion}
end
```

The signature verification in `verify_assertion_signature` happens on the extracted element,
but XSW attacks work by making the XPath resolve to a **different** element than what was signed.

**Fix:** Reject responses containing multiple assertions. Verify that the signed element and
the extracted element are the same node (compare by ID attribute).

---

#### 2.2 Missing NotBefore Time Validation

**File:** `lib/ex_saml/core/saml.ex` — `check_stale/1`, `stale_time/1`

The code decodes `NotBefore` from conditions but **never validates it**. Only the upper bound
(`NotOnOrAfter`) is checked. An assertion issued in the future would be accepted.

```elixir
# NotBefore is decoded (line 607) but never checked
|> maybe_add_condition(xml, "/saml:Conditions/@NotBefore", ns, :not_before, :attr)

# check_stale only validates upper bound
defp check_stale(%Assertion{} = a) do
  now_secs = ...
  t = stale_time(a)  # Only computes NotOnOrAfter
  if now_secs > t, do: {:error, :stale_assertion}, else: :ok
end
```

**Fix:** Add `validate_not_before/1` that checks `now >= NotBefore` (with small clock skew
tolerance).

---

### HIGH

#### 2.3 Optional Signature Verification

**File:** `lib/ex_saml/core/sp.ex` — `verify_envelope_signature/2`, `verify_assertion_signature/2`

Signature verification is controlled by config flags (`idp_signs_envelopes`,
`idp_signs_assertions`). When set to `false`, verification is completely skipped:

```elixir
defp verify_envelope_signature(xml, sp) do
  if sp.idp_signs_envelopes do
    # ... verify ...
  else
    :ok  # ACCEPTS UNSIGNED
  end
end
```

While defaults are `true`, several IdP provider types in `idp_data.ex` set both to `false`
(e.g., `ping_federate`, `ping_one`). A misconfiguration silently disables all signature
checking.

**Fix:** Log a warning when signature verification is disabled. Consider requiring at least
one of envelope or assertion signature to be verified.

---

#### 2.4 Certificate Validation Gaps

**File:** `lib/ex_saml/core/xml/dsig.ex` — `check_fingerprints/2`, `extract_public_key/2`

Problems:
1. `check_fingerprints(_cert_bin, :any)` accepts **any** valid certificate, including self-signed
2. No certificate chain validation (expiry, revocation)
3. No CN/SAN validation against IdP entity ID
4. The public key is extracted from the certificate **embedded in the signature itself** — an
   attacker who controls the XML can embed their own certificate

```elixir
defp check_fingerprints(_cert_bin, :any), do: :ok  # ACCEPTS ANY CERT
```

**Fix:** Always require fingerprint validation (never use `:any` in production). Add
certificate expiry checks.

---

### MEDIUM

#### 2.5 SHA-1 Signature Algorithm Still Supported

**File:** `lib/ex_saml/core/xml/dsig.ex` — `signature_props/1`

SHA-1 is cryptographically broken (SHAttered attack, 2017). The code accepts RSA-SHA1
signatures without warning:

```elixir
def signature_props(:rsa_sha1) do
  {:sha, "http://www.w3.org/2000/09/xmldsig#sha1",
   "http://www.w3.org/2000/09/xmldsig#rsa-sha1"}
end
```

**Fix:** Reject SHA-1 by default, or at minimum log a security warning. Add an algorithm
whitelist that only accepts SHA-256+.

---

#### 2.6 No Algorithm Whitelist in Verification

**File:** `lib/ex_saml/core/xml/dsig.ex` — `verify/2`

The verification function reads the algorithm from the signature itself and trusts it:

```elixir
[algo_attr] when Record.is_record(algo_attr, :xmlAttribute) ->
  {hash_function, _, _} = signature_props(xmlAttribute(algo_attr, :value))
```

An unknown algorithm would cause `signature_props` to crash (no matching clause). There is
no explicit whitelist of allowed algorithms.

**Fix:** Whitelist allowed algorithms explicitly and return `{:error, :unsupported_algorithm}`
for anything else.

---

#### 2.7 Default Replay Detection Disabled

**File:** `lib/ex_saml/core/sp.ex` — `validate_assertion/2`

The default duplicate detection function is a no-op:

```elixir
def validate_assertion(xml, %SpConfig{} = sp) do
  validate_assertion(xml, fn _a, _digest -> :ok end, sp)  # NO-OP
end
```

While `ExSaml.Core.Util.check_dupe_ets/2` exists, it's never used by default. Replay attacks
are possible out of the box.

**Fix:** Use `check_dupe_ets` as the default duplicate detection function.

---

#### 2.8 Comment Injection in NameID

**File:** `lib/ex_saml/core/saml.ex` — `decode_assertion_subject/1`

NameID is extracted from XML text nodes without comment filtering:

```elixir
name = case xpath_text(xml, "/saml:Subject/saml:NameID/text()", ns) do
  {:ok, v} -> v
  :not_found -> ""
end
```

An attacker could craft a NameID like `admin<!-- comment -->@evil.com` that might be
interpreted differently by different consumers. While canonicalization strips comments before
signature verification, the extracted value after parsing could still contain artifacts.

**Fix:** Strip XML comments and normalize whitespace in all extracted text values.

---

### LOW

#### 2.9 PKCS#7 Padding Oracle Risk

**File:** `lib/ex_saml/core/sp.ex` — `strip_pkcs7_padding/1`

The PKCS#7 padding removal is non-standard:

```elixir
defp strip_pkcs7_padding(data) when is_binary(data) do
  data
  |> :binary.bin_to_list()
  |> Enum.reverse()
  |> Enum.drop_while(fn x -> x < 16 end)
  |> Enum.reverse()
  |> :erlang.list_to_binary()
end
```

This drops all trailing bytes < 16 instead of checking the PKCS#7 padding format (last byte
= N, last N bytes all = N). While exploitation is limited because all errors return the same
`:bad_assertion` error, the implementation is incorrect.

**Fix:** Implement proper PKCS#7 padding validation.

---

## 3. Prioritized Fix Plan

| Priority | Issue | Effort |
|----------|-------|--------|
| P0 | 2.1 XXE — add `allow_entities: false` to xmerl_scan calls | Small |
| P0 | 2.1 XSW — reject multiple assertions, verify extracted = signed | Medium |
| P0 | 2.2 NotBefore — add time lower bound validation | Small |
| P1 | 2.3 Optional signatures — add warnings, require at least one | Small |
| P1 | 2.4 Certificate — require fingerprints, check expiry | Medium |
| P1 | 2.5 SHA-1 — reject or warn | Small |
| P1 | 2.6 Algorithm whitelist | Small |
| P1 | 2.7 Replay detection — enable by default | Small |
| P2 | 2.8 Comment injection — normalize text values | Small |
| P2 | 2.9 PKCS#7 padding — proper validation | Small |

---

## References

- [CVE-2026-28809 — EEF Advisory](https://cna.erlef.org/cves/CVE-2026-28809.html)
- [GHSA-4g2h-vm7x-747c](https://github.com/advisories/GHSA-4g2h-vm7x-747c)
- [erlang/otp#7539 — xmerl XXE default](https://github.com/erlang/otp/issues/7539)
- [PortSwigger — The Fragile Lock: Novel Bypasses For SAML Authentication](https://portswigger.net/research/the-fragile-lock)
- [SHAttered — SHA-1 collision attack](https://shattered.io/)
