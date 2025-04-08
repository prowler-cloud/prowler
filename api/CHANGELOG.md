# Prowler API Changelog

All notable changes to the **Prowler API** are documented in this file.

---

## [v1.5.4] (Prowler v5.4.4)

### Fixed
- Fixed a bug with periodic tasks when trying to delete a provider ([#7466])(https://github.com/prowler-cloud/prowler/pull/7466).

---

## [v1.5.3] (Prowler v5.4.3)

### Fixed
- Added duplicated scheduled scans handling ([#7401])(https://github.com/prowler-cloud/prowler/pull/7401).
- Added environment variable to configure the deletion task batch size ([#7423])(https://github.com/prowler-cloud/prowler/pull/7423).

---

## [v1.5.2] (Prowler v5.4.2)

### Changed
- Refactored deletion logic and implemented retry mechanism for deletion tasks [(#7349)](https://github.com/prowler-cloud/prowler/pull/7349).

---

## [v1.5.1] (Prowler v5.4.1)

### Fixed
- Added a handled response in case local files are missing [(#7183)](https://github.com/prowler-cloud/prowler/pull/7183).
- Fixed a race condition when deleting export files after the S3 upload [(#7172)](https://github.com/prowler-cloud/prowler/pull/7172).
- Handled exception when a provider has no secret in test connection [(#7283)](https://github.com/prowler-cloud/prowler/pull/7283).


---

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
