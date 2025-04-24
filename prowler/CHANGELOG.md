# Prowler SDK Changelog

All notable changes to the **Prowler SDK** are documented in this file.

## [v5.6.0] (Prowler UNRELEASED)

### Added

- Add SOC2 compliance framework to Azure [(#7489)](https://github.com/prowler-cloud/prowler/pull/7489).
- Add check for unused Service Accounts in GCP [(#7419)](https://github.com/prowler-cloud/prowler/pull/7419).
- Add Powershell to Microsoft365 [(#7331)](https://github.com/prowler-cloud/prowler/pull/7331).
- Add service Defender to Microsoft365 with one check for Common Attachments filter enabled in Malware Policies [(#7425)](https://github.com/prowler-cloud/prowler/pull/7425).
- Add check for Outbound Antispam Policy well configured in service Defender for M365 [(#7480)](https://github.com/prowler-cloud/prowler/pull/7480).
- Add check for Antiphishing Policy well configured in service Defender in M365 [(#7453)](https://github.com/prowler-cloud/prowler/pull/7453).
- Add check for Notifications for Internal users enabled in Malware Policies from service Defender in M365 [(#7435)](https://github.com/prowler-cloud/prowler/pull/7435).
- Support CLOUDSDK_AUTH_ACCESS_TOKEN in GCP [(#7495)](https://github.com/prowler-cloud/prowler/pull/7495).
- Add service Exchange to Microsoft365 with one check for Organizations Mailbox Auditing enabled [(#7408)](https://github.com/prowler-cloud/prowler/pull/7408)
- Add check for Bypass Disable in every Mailbox for service Defender in M365 [(#7418)](https://github.com/prowler-cloud/prowler/pull/7418)
- Add new check `teams_external_domains_restricted` [(#7557)](https://github.com/prowler-cloud/prowler/pull/7557)
- Add new check `teams_email_sending_to_channel_disabled` [(#7533)](https://github.com/prowler-cloud/prowler/pull/7533)
- Add new check for External Mails Tagged for service Exchange in M365 [(#7580)](https://github.com/prowler-cloud/prowler/pull/7580)
- Add new check for WhiteList not used in Transport Rules for service Defender in M365 [(#7569)](https://github.com/prowler-cloud/prowler/pull/7569)
- Add check for Inbound Antispam Policy with no allowed domains from service Defender in M365 [(#7500)](https://github.com/prowler-cloud/prowler/pull/7500)
- Add new check `teams_meeting_anonymous_user_join_disabled` [(#7565)](https://github.com/prowler-cloud/prowler/pull/7565)
- Add new check `teams_unmanaged_communication_disabled` [(#7561)](https://github.com/prowler-cloud/prowler/pull/7561)
- Add new check `teams_external_users_cannot_start_conversations` [(#7562)](https://github.com/prowler-cloud/prowler/pull/7562)
- Add new check for AllowList not used in the Connection Filter Policy from service Defender in M365 [(#7492)](https://github.com/prowler-cloud/prowler/pull/7492)
- Add new check for SafeList not enabled in the Connection Filter Policy from service Defender in M365 [(#7492)](https://github.com/prowler-cloud/prowler/pull/7492)
- Add new check for DKIM enabled for service Defender in M365 [(#7485)](https://github.com/prowler-cloud/prowler/pull/7485)
- Add new check `teams_meeting_anonymous_user_start_disabled` [(#7567)](https://github.com/prowler-cloud/prowler/pull/7567)
- Add new check `teams_meeting_external_lobby_bypass_disabled` [(#7568)](https://github.com/prowler-cloud/prowler/pull/7568)

### Fixed

- Fix package name location in pyproject.toml while replicating for prowler-cloud [(#7531)](https://github.com/prowler-cloud/prowler/pull/7531).
- Remove cache in PyPI release action [(#7532)](https://github.com/prowler-cloud/prowler/pull/7532).
- Add the correct values for logger.info inside iam service [(#7526)](https://github.com/prowler-cloud/prowler/pull/7526).
- Update S3 bucket naming validation to accept dots [(#7545)](https://github.com/prowler-cloud/prowler/pull/7545).
- Handle new FlowLog model properties in Azure [(#7546)](https://github.com/prowler-cloud/prowler/pull/7546).
- Remove first empty line in HTML output [(#7606)](https://github.com/prowler-cloud/prowler/pull/7606)
- Remove invalid parameter `create_file_descriptor` in NHN provider [(#7600)](https://github.com/prowler-cloud/prowler/pull/7600)

---

## [v5.5.1] (Prowler v5.5.1)

### Fixed

- Add default name to contacts in Azure Defender [(#7483)](https://github.com/prowler-cloud/prowler/pull/7483).
- Handle projects without ID in GCP [(#7496)](https://github.com/prowler-cloud/prowler/pull/7496).
- Restore packages location in PyProject [(#7510)](https://github.com/prowler-cloud/prowler/pull/7510).

---
