# Prowler SDK Changelog

All notable changes to the **Prowler SDK** are documented in this file.

## [v5.6.0] (Prowler UNRELEASED)

### Added

- Add SOC2 compliance framework to Azure [(#7489)](https://github.com/prowler-cloud/prowler/pull/7489).
- Add check for unused Service Accounts in GCP [(#7419)](https://github.com/prowler-cloud/prowler/pull/7419).

### Fixed

- Fix package name location in pyproject.toml while replicating for prowler-cloud [(#7531)](https://github.com/prowler-cloud/prowler/pull/7531).
- Remove cache in PyPI release action [(#7532)](https://github.com/prowler-cloud/prowler/pull/7532).
- Add the correct values for logger.info inside iam service [(#7526)](https://github.com/prowler-cloud/prowler/pull/7526).
- Update S3 bucket naming validation to accept dots [(#7545)](https://github.com/prowler-cloud/prowler/pull/7545).
- Handle new FlowLog model properties in Azure [(#7546)](https://github.com/prowler-cloud/prowler/pull/7546).
- Improve compliance and dashboard [(#7596)](https://github.com/prowler-cloud/prowler/pull/7596)
- Remove invalid parameter `create_file_descriptor` [(#7600)](https://github.com/prowler-cloud/prowler/pull/7600)
- Remove first empty line in HTML output [(#7606)](https://github.com/prowler-cloud/prowler/pull/7606)
- Ensure that ContentType in upload_file matches the uploaded file’s format [(#7635)](https://github.com/prowler-cloud/prowler/pull/7635)

---

## [v5.5.1] (Prowler v5.5.1)

### Fixed

- Add default name to contacts in Azure Defender [(#7483)](https://github.com/prowler-cloud/prowler/pull/7483).
- Handle projects without ID in GCP [(#7496)](https://github.com/prowler-cloud/prowler/pull/7496).
- Restore packages location in PyProject [(#7510)](https://github.com/prowler-cloud/prowler/pull/7510).

---
