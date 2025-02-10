# Prowler API Changelog

All notable changes to the **Prowler API** are documented in this file.

---

## [Unreleased]


---

## [v1.5.0] (Prowler v5.4.0) - 2025-XX-XX

### Added
- Add API scan report system, now all scans launched from the API will generate a compressed file with the report in OCSF, CSV and HTML formats [(#6878)](https://github.com/prowler-cloud/prowler/pull/6878).

---

## [v1.4.0] (Prowler v5.3.0) - 2025-02-10

### Changed
- Daily scheduled scan instances are now created beforehand with `SCHEDULED` state [(#6700)](https://github.com/prowler-cloud/prowler/pull/6700).
- Findings endpoints now require at least one date filter [(#6800)](https://github.com/prowler-cloud/prowler/pull/6800).
- Findings metadata endpoint received a performance improvement [(#6863)](https://github.com/prowler-cloud/prowler/pull/6863).
- Increase the allowed length of the provider UID for Kubernetes providers [(#6869)](https://github.com/prowler-cloud/prowler/pull/6869).

---
