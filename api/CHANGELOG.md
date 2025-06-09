# Prowler API Changelog

All notable changes to the **Prowler API** are documented in this file.

## [v1.9.0] (Prowler UNRELEASED)

### Added
- Support GCP Service Account key. [(#7824)](https://github.com/prowler-cloud/prowler/pull/7824)
- Added new `GET /compliance-overviews` endpoints to retrieve compliance metadata and specific requirements statuses [(#7877)](https://github.com/prowler-cloud/prowler/pull/7877).

### Changed
- Reworked `GET /compliance-overviews` to return proper requirement metrics [(#7877)](https://github.com/prowler-cloud/prowler/pull/7877).

---

## [v1.8.3] (Prowler v5.7.3)

### Added
- Database backend to handle already closed connections [(#7935)](https://github.com/prowler-cloud/prowler/pull/7935).

### Changed
- Renamed field encrypted_password to password for M365 provider [(#7784)](https://github.com/prowler-cloud/prowler/pull/7784)

### Fixed
- Fixed transaction persistence with RLS operations [(#7916)](https://github.com/prowler-cloud/prowler/pull/7916).
- Reverted the change `get_with_retry` to use the original `get` method for retrieving tasks [(#7932)](https://github.com/prowler-cloud/prowler/pull/7932).


---

## [v1.8.2] (Prowler v5.7.2)

### Fixed
- Fixed task lookup to use task_kwargs instead of task_args for scan report resolution. [(#7830)](https://github.com/prowler-cloud/prowler/pull/7830)
- Fixed Kubernetes UID validation to allow valid context names [(#7871)](https://github.com/prowler-cloud/prowler/pull/7871)
- Fixed the connection status verification before launching a scan [(#7831)](https://github.com/prowler-cloud/prowler/pull/7831)
- Fixed a race condition when creating background tasks [(#7876)](https://github.com/prowler-cloud/prowler/pull/7876).
- Fixed an error when modifying or retrieving tenants due to missing user UUID in transaction context [(#7890)](https://github.com/prowler-cloud/prowler/pull/7890).

---

## [v1.8.1] (Prowler v5.7.1)

### Fixed
- Added database index to improve performance on finding lookup [(#7800)](https://github.com/prowler-cloud/prowler/pull/7800).

---

## [v1.8.0] (Prowler v5.7.0)

### Added
- Added huge improvements to `/findings/metadata` and resource related filters for findings [(#7690)](https://github.com/prowler-cloud/prowler/pull/7690).
- Added improvements to `/overviews` endpoints [(#7690)](https://github.com/prowler-cloud/prowler/pull/7690).
- Added new queue to perform backfill background tasks [(#7690)](https://github.com/prowler-cloud/prowler/pull/7690).
- Added new endpoints to retrieve latest findings and metadata [(#7743)](https://github.com/prowler-cloud/prowler/pull/7743).
- Added export support for Prowler ThreatScore in M365 [(7783)](https://github.com/prowler-cloud/prowler/pull/7783)

---

## [v1.7.0] (Prowler v5.6.0)

### Added

- Added M365 as a new provider [(#7563)](https://github.com/prowler-cloud/prowler/pull/7563).
- Added a `compliance/` folder and ZIP‐export functionality for all compliance reports.[(#7653)](https://github.com/prowler-cloud/prowler/pull/7653).
- Added a new API endpoint to fetch and download any specific compliance file by name [(#7653)](https://github.com/prowler-cloud/prowler/pull/7653).

---

## [v1.6.0] (Prowler v5.5.0)

### Added

- Support for developing new integrations [(#7167)](https://github.com/prowler-cloud/prowler/pull/7167).
- HTTP Security Headers [(#7289)](https://github.com/prowler-cloud/prowler/pull/7289).
- New endpoint to get the compliance overviews metadata [(#7333)](https://github.com/prowler-cloud/prowler/pull/7333).
- Support for muted findings [(#7378)](https://github.com/prowler-cloud/prowler/pull/7378).
- Added missing fields to API findings and resources [(#7318)](https://github.com/prowler-cloud/prowler/pull/7318).

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
- Increased the allowed length of the provider UID for Kubernetes providers [(#6869)](https://github.com/prowler-cloud/prowler/pull/6869).

---
