# Prowler API Changelog

All notable changes to the **Prowler API** are documented in this file.

---

<<<<<<< HEAD
=======
## [v1.6.0] (Prowler UNRELEASED)

### Added

- Support for developing new integrations [(#7167)](https://github.com/prowler-cloud/prowler/pull/7167).

---

## [v1.5.1] (Prowler v5.4.1)

### Fixed
- Fixed a race condition when deleting export files after the S3 upload [(#7172)](https://github.com/prowler-cloud/prowler/pull/7172).

---

>>>>>>> 07419fd5e (fix(exports): change the way to remove the local export files after s3 upload (#7172))
## [v1.5.0] (Prowler v5.4.0)

### Added
- Social login integration with Google and GitHub [(#6906)](https://github.com/prowler-cloud/prowler/pull/6906)
- Add API scan report system, now all scans launched from the API will generate a compressed file with the report in OCSF, CSV and HTML formats [(#6878)](https://github.com/prowler-cloud/prowler/pull/6878).
- Configurable Sentry integration [(#6874)](https://github.com/prowler-cloud/prowler/pull/6874)

### Changed
- Optimized `GET /findings` endpoint to improve response time and size [(#7019)](https://github.com/prowler-cloud/prowler/pull/7019).

---

## [v1.4.0] (Prowler v5.3.0)

### Changed
- Daily scheduled scan instances are now created beforehand with `SCHEDULED` state [(#6700)](https://github.com/prowler-cloud/prowler/pull/6700).
- Findings endpoints now require at least one date filter [(#6800)](https://github.com/prowler-cloud/prowler/pull/6800).
- Findings metadata endpoint received a performance improvement [(#6863)](https://github.com/prowler-cloud/prowler/pull/6863).
- Increase the allowed length of the provider UID for Kubernetes providers [(#6869)](https://github.com/prowler-cloud/prowler/pull/6869).

---
