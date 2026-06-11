# Changelog

## [0.0.3] - 2026-06-11

### Added

- Added `--json` output mode for machine-readable reports.
- Added `--output` / `-o` for saving JSON reports to a file.
- Added JSON serialization helpers with stable report fields.
- Added a legitimate-domain allowlist to reduce brand-impersonation false positives.
- Added tests for JSON reports, unsupported URL schemes, GitLab false positives and delivery-style suspicious URLs.

### Changed

- Renamed user-facing `Evidence confidence` to `Evidence coverage`.
- Updated package version from `0.0.2` to `0.0.3`.
- Updated the built-in popularity text so it no longer references old internal versions.
- Updated the HTTP User-Agent to use the package version dynamically.
- Improved suspicious delivery/shipping keyword coverage.
- Reduced the HTTP-only URL penalty to make scoring less aggressive for static-only checks.

### Fixed

- Fixed a false positive where `gitlab.com` could be treated as GitHub impersonation.
- Rejected non-HTTP URL schemes during normalization instead of accepting unsupported targets.

## [0.0.2] - 2026-06-10

### Added

- Added WHOIS checks.
- Added domain age analysis.
- Added registrar detection.
- Added domain expiry checks.
- Added TLS certificate checks.
- Added certificate expiry scoring.
- Added richer DNS probing:
  - A records
  - AAAA records
  - NS records
  - MX records
  - CNAME records
  - private/local IP detection
- Added improved HTTP probing:
  - final URL detection
  - redirect count
  - redirect chain storage
  - content type detection
  - response headers collection
- Added basic HTML content inspection:
  - password input detection
  - external form action detection
  - hidden input counting
  - iframe counting
  - suspicious page text signals
- Added basic security header check for `Content-Security-Policy`.
- Added `--no-content` CLI option.
- Added `--timeout` CLI option.
- Added evidence confidence score.
- Added tests for private IP detection.
- Added tests for WHOIS date parsing.

### Changed

- Updated package version from `0.0.1` to `0.0.2`.
- Updated CLI description from URL-only checker to threat analysis toolkit.
- Updated README to describe the broader v0.0.2 checks.
- Updated warning text to avoid unrealistic safety guarantees.

### Notes

SuspicionKit still does not guarantee that a URL is safe. The new checks make the report more useful, but real-world phishing can still evade lightweight static and network-based analysis.
