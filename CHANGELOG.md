# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.2] - 2026-04-16

### Security

- Fix XXE vulnerability ([CVE-2026-28809](https://cna.erlef.org/cves/CVE-2026-28809.html)) — add `allow_entities: false` to all `xmerl_scan.string` calls
- Add `NotBefore` time validation on assertions with 5-second clock skew tolerance
- Add algorithm whitelist — unknown signature algorithms now return `{:error, :unsupported_algorithm}` instead of crashing

## [1.0.1] - 2026-04-09

### Changed

- Fork `esaml` Erlang dependency into the project to remove unmaintained external dependency

### Fixed

- Audit issues from security review (#7)

## [1.0.0] - 2026-03-20

### Added

- Initial release as ExSaml, successor to [Samly](https://hex.pm/packages/samly)
- SP-initiated and IdP-initiated SSO flows
- Single Logout (SLO) support
- SP metadata generation
- Multi-IdP support with per-IdP configuration
- Pluggable assertion storage (ETS, Session, Nebulex cache)
- Relay state cache with anti-replay protection (`RelayStateCache.take/1`)
- Security headers plug (CSP with nonce, X-Frame-Options)
- Cryptographic nonce validation during auth flow
- Configurable cache backend via `config.exs`
- RSA-SHA1 signature rejection with `{:error, :insecure_algorithm}`
- Migration guide from Samly
- Module documentation across all public modules

### Removed

- Unused routes and pre-session create pipeline from Samly
- Hardcoded Nebulex cache — replaced with delegate pattern

[1.0.2]: https://github.com/docJerem/ex_saml/compare/v1.0.1...v1.0.2
[1.0.1]: https://github.com/docJerem/ex_saml/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/docJerem/ex_saml/releases/tag/v1.0.0
