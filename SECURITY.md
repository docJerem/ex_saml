# Security Policy

`ex_saml` is a SAML 2.0 **Service Provider (SP)** library. It consumes and
validates IdP-issued SAML responses/assertions and produces SP requests and
metadata. Because it sits directly on an authentication trust boundary, this
document states what the library defends against, where the trust boundary
sits, and how to report issues.

## Supported versions

| Version | Supported |
|---------|-----------|
| latest `1.x` | ✅ security fixes |
| `< 1.0` | ❌ |

## Reporting a vulnerability

Please report suspected vulnerabilities **privately** — do not open a public
issue for an unpatched flaw.

- Open a [GitHub security advisory](https://github.com/docJerem/ex_saml/security/advisories/new), or
- email the maintainer (see the repository owner's profile).

Include: affected version, a description, and a proof-of-concept if possible.
We aim to acknowledge within a few business days and to coordinate a fix and
disclosure timeline with you.

## Threat model

The SP consumes attacker-reachable input: an IdP `SAMLResponse` POSTed (or
redirected) to the ACS endpoint. The following classes are explicitly in
scope.

| Threat | Defense | Where |
|--------|---------|-------|
| **XXE / external entities** (external/parameter entities, external DTD) | `:xmerl_scan` is always called with `allow_entities: false` (and `namespace_conformant: true`) | `Core.Binding`, `Core.Sp`, `Metadata` |
| **Entity-expansion DoS** (billion-laughs) | Same — entity expansion is disabled, so nested/expanding entities cannot be processed | as above |
| **Signature forgery** | Signatures are verified with `:public_key.verify/4`; a forged/incorrect signature fails | `Core.Xml.Dsig.verify/2` |
| **Weak signature algorithms** | **RSA-SHA1 is rejected** as cryptographically broken; RSA-SHA256 is accepted | `Core.Xml.Dsig` |
| **Key substitution via document `KeyInfo`** | Trust is bound to the **configured IdP certificate fingerprints**, never to a document-supplied `KeyInfo`. The certificate carried in the signature is compared against the SP config's `trusted_fingerprints` before the assertion is trusted | `Dsig.check_fingerprints/2`, `IdpData` |
| **IdP / issuer confusion** | The assertion `Issuer` is validated against the configured IdP `entity_id` when available | `Core.Saml.validate_assertion/4` |
| **Audience / recipient / destination misuse** | `Recipient` must match the SP ACS; `Audience` is checked against the SP entity id when present | `Core.Saml` |
| **Time-based replay / stale assertions** | `NotBefore` (with small skew) and `NotOnOrAfter` are enforced | `Core.Saml` |
| **RelayState / one-time consumption** | Anti-replay of the transaction is delegated to the injected state cache (consumer-provided) | consumer + `ExSaml.State` |

### Trust boundary

> **Signatures are only ever trusted when the signing certificate matches a
> fingerprint configured for that IdP.** The library never derives trust from
> data supplied inside the document (e.g. an inline `KeyInfo`/certificate that
> the response itself carries). This is the single most important invariant:
> attacker-supplied XML cannot introduce a key the SP will trust.

## Known hardening in progress

These are tracked as open work and are **not yet complete**:

- **XML Signature Wrapping (XSW)** — making the "verified node == consumed
  node" binding explicit and adding a dedicated XSW test corpus (#39).
- **Adversarial XML corpus in CI** — a versioned fixture set (XXE, DOCTYPE,
  entity expansion, encoding, c14n golden outputs) run on every build (#38).
- **Parsing-surface centralisation + audit gate** — a single hardened parse
  entry point and a CI check forbidding new unhardened `:xmerl_scan` sites
  (#32).

## Algorithm policy

| Purpose | Accepted | Rejected |
|---------|----------|----------|
| Signature | RSA-SHA256 | RSA-SHA1 (broken) |
| Digest | SHA-256 | SHA-1 |

## Non-goals

`ex_saml` is a SAML **SP** library only. Out of scope:

- Acting as an Identity Provider (IdP).
- OIDC / OAuth 2.0 flows.
- Session management, user storage, or authorization decisions (the consuming
  application owns these).
- Transport security (TLS termination), which is the deployment's
  responsibility.

## Coordinated disclosure

We follow coordinated disclosure. After a fix ships, a write-up is published
under [`docs/advisories/`](docs/advisories/) following
[`docs/advisories/TEMPLATE.md`](docs/advisories/TEMPLATE.md): root cause,
impact, affected versions, and the fix.
