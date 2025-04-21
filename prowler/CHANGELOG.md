# Prowler SDK Changelog

All notable changes to the **Prowler SDK** are documented in this file.

## [v5.6.0] (Prowler UNRELEASED)

### Added

- Add SOC2 compliance framework to Azure [(#7489)](https://github.com/prowler-cloud/prowler/pull/7489).
- Add check for unused Service Accounts in GCP [(#7419)](https://github.com/prowler-cloud/prowler/pull/7419).
- Add Powershell to Microsoft365 [(#7331)](https://github.com/prowler-cloud/prowler/pull/7331).
- Add service Defender to Microsoft365 with one check for Common Attachments filter enabled in Malware Policies [(#7425)](https://github.com/prowler-cloud/prowler/pull/7425).
- Add check for Antiphishing Policy well configured in service Defender in M365 [(#7453)](https://github.com/prowler-cloud/prowler/pull/7453).
- Add check for Notifications for Internal users enabled in Malware Policies from service Defender in M365 [(#7435)](https://github.com/prowler-cloud/prowler/pull/7435).
- Support CLOUDSDK_AUTH_ACCESS_TOKEN in GCP [(#7495)](https://github.com/prowler-cloud/prowler/pull/7495).
- Add service Exchange to Microsoft365 with one check for Organizations Mailbox Auditing enabled [(#7408)](https://github.com/prowler-cloud/prowler/pull/7408)
- Add check for Bypass Disable in every Mailbox for service Defender in M365 [(#7418)](https://github.com/prowler-cloud/prowler/pull/7418)
- Add new check `teams_email_sending_to_channel_disabled` [(#7533)](https://github.com/prowler-cloud/prowler/pull/7533)
- Add new check `teams_unmanaged_communication_disabled` [(#7561)](https://github.com/prowler-cloud/prowler/pull/7561)
- Add new check `teams_external_users_cannot_start_conversations` [(#7562)](https://github.com/prowler-cloud/prowler/pull/7562)
### Fixed

- Fix package name location in pyproject.toml while replicating for prowler-cloud [(#7531)](https://github.com/prowler-cloud/prowler/pull/7531).
- Remove cache in PyPI release action [(#7532)](https://github.com/prowler-cloud/prowler/pull/7532).
- Add the correct values for logger.info inside iam service [(#7526)](https://github.com/prowler-cloud/prowler/pull/7526).

---

## [v5.5.1] (Prowler v5.5.1)

### Fixed

- Add default name to contacts in Azure Defender [(#7483)](https://github.com/prowler-cloud/prowler/pull/7483).
- Handle projects without ID in GCP [(#7496)](https://github.com/prowler-cloud/prowler/pull/7496).
- Restore packages location in PyProject [(#7510)](https://github.com/prowler-cloud/prowler/pull/7510).

---
