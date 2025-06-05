# Prowler SDK Changelog

All notable changes to the **Prowler SDK** are documented in this file.

## [v5.8.0] (Prowler UNRELEASED)

### Added
- Add CIS 1.11 compliance framework for Kubernetes. [(#7790)](https://github.com/prowler-cloud/prowler/pull/7790)
- Support `HTTPS_PROXY` and `K8S_SKIP_TLS_VERIFY` in Kubernetes. [(#7720)](https://github.com/prowler-cloud/prowler/pull/7720)
- Add Weight for Prowler ThreatScore scoring. [(#7795)](https://github.com/prowler-cloud/prowler/pull/7795)
- Add new check `entra_users_mfa_capable` for M365 provider. [(#7734)](https://github.com/prowler-cloud/prowler/pull/7734)
- Add new check `admincenter_organization_customer_lockbox_enabled` for M365 provider. [(#7732)](https://github.com/prowler-cloud/prowler/pull/7732)
- Add new check `admincenter_external_calendar_sharing_disabled` for M365 provider. [(#7733)](https://github.com/prowler-cloud/prowler/pull/7733)
- Add a level for Prowler ThreatScore in the accordion in Dashboard. [(#7739)](https://github.com/prowler-cloud/prowler/pull/7739)
- Add CIS 4.0 compliance framework for GCP. [(7785)](https://github.com/prowler-cloud/prowler/pull/7785)
- Add `repository_has_codeowners_file` check for GitHub provider. [(#7752)](https://github.com/prowler-cloud/prowler/pull/7752)
- Add `repository_default_branch_requires_signed_commits` check for GitHub provider. [(#7777)](https://github.com/prowler-cloud/prowler/pull/7777)
- Add `repository_inactive_not_archived` check for GitHub provider. [(#7786)](https://github.com/prowler-cloud/prowler/pull/7786)
- Add `repository_dependency_scanning_enabled` check for GitHub provider. [(#7771)](https://github.com/prowler-cloud/prowler/pull/7771)
- Add `repository_secret_scanning_enabled` check for GitHub provider. [(#7759)](https://github.com/prowler-cloud/prowler/pull/7759)
- Add `repository_default_branch_requires_codeowners_review` check for GitHub provider. [(#7753)](https://github.com/prowler-cloud/prowler/pull/7753)
- Add NIS 2 compliance framework for AWS. [(#7839)](https://github.com/prowler-cloud/prowler/pull/7839)
- Add NIS 2 compliance framework for Azure. [(#7857)](https://github.com/prowler-cloud/prowler/pull/7857)
- Add search bar in Dashboard Overview page. [(#7804)](https://github.com/prowler-cloud/prowler/pull/7804)

### Fixed
- Add github provider to `usage` section of `prowler -h`: [(#7906)](https://github.com/prowler-cloud/prowler/pull/7906)

---

## [v5.7.3] (Prowler v5.7.3)

### Fixed
- Automatically encrypt password in Microsoft365 provider. [(#7784)](https://github.com/prowler-cloud/prowler/pull/7784)
- Remove last encrypted password appearances. [(#7825)](https://github.com/prowler-cloud/prowler/pull/7825)

---

## [v5.7.2] (Prowler v5.7.2)

### Fixed
- Fix `m365_powershell test_credentials` to use sanitized credentials. [(#7761)](https://github.com/prowler-cloud/prowler/pull/7761)
- Fix `admincenter_users_admins_reduced_license_footprint` check logic to pass when admin user has no license. [(#7779)](https://github.com/prowler-cloud/prowler/pull/7779)
- Fix `m365_powershell` to close the PowerShell sessions in msgraph services. [(#7816)](https://github.com/prowler-cloud/prowler/pull/7816)
- Fix `defender_ensure_notify_alerts_severity_is_high`check to accept high or lower severity. [(#7862)](https://github.com/prowler-cloud/prowler/pull/7862)
- Replace `Directory.Read.All` permission with `Domain.Read.All` which is more restrictive. [(#7888)](https://github.com/prowler-cloud/prowler/pull/7888)
- Split calls to list Azure Functions attributes. [(#7778)](https://github.com/prowler-cloud/prowler/pull/7778)

---

## [v5.7.0] (Prowler v5.7.0)

### Added
- Update the compliance list supported for each provider from docs. [(#7694)](https://github.com/prowler-cloud/prowler/pull/7694)
- Allow setting cluster name in in-cluster mode in Kubernetes. [(#7695)](https://github.com/prowler-cloud/prowler/pull/7695)
- Add Prowler ThreatScore for M365 provider. [(#7692)](https://github.com/prowler-cloud/prowler/pull/7692)
- Add GitHub provider. [(#5787)](https://github.com/prowler-cloud/prowler/pull/5787)
- Add `repository_default_branch_requires_multiple_approvals` check for GitHub provider. [(#6160)](https://github.com/prowler-cloud/prowler/pull/6160)
- Add `repository_default_branch_protection_enabled` check for GitHub provider. [(#6161)](https://github.com/prowler-cloud/prowler/pull/6161)
- Add `repository_default_branch_requires_linear_history` check for GitHub provider. [(#6162)](https://github.com/prowler-cloud/prowler/pull/6162)
- Add `repository_default_branch_disallows_force_push` check for GitHub provider. [(#6197)](https://github.com/prowler-cloud/prowler/pull/6197)
- Add `repository_default_branch_deletion_disabled` check for GitHub provider. [(#6200)](https://github.com/prowler-cloud/prowler/pull/6200)
- Add `repository_default_branch_status_checks_required` check for GitHub provider. [(#6204)](https://github.com/prowler-cloud/prowler/pull/6204)
- Add `repository_default_branch_protection_applies_to_admins` check for GitHub provider. [(#6205)](https://github.com/prowler-cloud/prowler/pull/6205)
- Add `repository_branch_delete_on_merge_enabled` check for GitHub provider. [(#6209)](https://github.com/prowler-cloud/prowler/pull/6209)
- Add `repository_default_branch_requires_conversation_resolution` check for GitHub provider. [(#6208)](https://github.com/prowler-cloud/prowler/pull/6208)
- Add `organization_members_mfa_required` check for GitHub provider. [(#6304)](https://github.com/prowler-cloud/prowler/pull/6304)
- Add GitHub provider documentation and CIS v1.0.0 compliance. [(#6116)](https://github.com/prowler-cloud/prowler/pull/6116)
- Add CIS 5.0 compliance framework for AWS. [(7766)](https://github.com/prowler-cloud/prowler/pull/7766)

### Fixed
- Update CIS 4.0 for M365 provider. [(#7699)](https://github.com/prowler-cloud/prowler/pull/7699)
- Update and upgrade CIS for all the providers [(#7738)](https://github.com/prowler-cloud/prowler/pull/7738)
- Cover policies with conditions with SNS endpoint in `sns_topics_not_publicly_accessible`. [(#7750)](https://github.com/prowler-cloud/prowler/pull/7750)
- Change severity logic for `ec2_securitygroup_allow_ingress_from_internet_to_all_ports` check. [(#7764)](https://github.com/prowler-cloud/prowler/pull/7764)

---

## [v5.6.0] (Prowler v5.6.0)

### Added
- Add SOC2 compliance framework to Azure. [(#7489)](https://github.com/prowler-cloud/prowler/pull/7489)
- Add check for unused Service Accounts in GCP. [(#7419)](https://github.com/prowler-cloud/prowler/pull/7419)
- Add Powershell to Microsoft365. [(#7331)](https://github.com/prowler-cloud/prowler/pull/7331)
- Add service Defender to Microsoft365 with one check for Common Attachments filter enabled in Malware Policies. [(#7425)](https://github.com/prowler-cloud/prowler/pull/7425)
- Add check for Outbound Antispam Policy well configured in service Defender for M365. [(#7480)](https://github.com/prowler-cloud/prowler/pull/7480)
- Add check for Antiphishing Policy well configured in service Defender in M365. [(#7453)](https://github.com/prowler-cloud/prowler/pull/7453)
- Add check for Notifications for Internal users enabled in Malware Policies from service Defender in M365. [(#7435)](https://github.com/prowler-cloud/prowler/pull/7435)
- Add support CLOUDSDK_AUTH_ACCESS_TOKEN in GCP. [(#7495)](https://github.com/prowler-cloud/prowler/pull/7495)
- Add service Exchange to Microsoft365 with one check for Organizations Mailbox Auditing enabled. [(#7408)](https://github.com/prowler-cloud/prowler/pull/7408)
- Add check for Bypass Disable in every Mailbox for service Defender in M365. [(#7418)](https://github.com/prowler-cloud/prowler/pull/7418)
- Add new check `teams_external_domains_restricted`. [(#7557)](https://github.com/prowler-cloud/prowler/pull/7557)
- Add new check `teams_email_sending_to_channel_disabled`. [(#7533)](https://github.com/prowler-cloud/prowler/pull/7533)
- Add new check for External Mails Tagged for service Exchange in M365. [(#7580)](https://github.com/prowler-cloud/prowler/pull/7580)
- Add new check for WhiteList not used in Transport Rules for service Defender in M365. [(#7569)](https://github.com/prowler-cloud/prowler/pull/7569)
- Add check for Inbound Antispam Policy with no allowed domains from service Defender in M365. [(#7500)](https://github.com/prowler-cloud/prowler/pull/7500)
- Add new check `teams_meeting_anonymous_user_join_disabled`. [(#7565)](https://github.com/prowler-cloud/prowler/pull/7565)
- Add new check `teams_unmanaged_communication_disabled`. [(#7561)](https://github.com/prowler-cloud/prowler/pull/7561)
- Add new check `teams_external_users_cannot_start_conversations`. [(#7562)](https://github.com/prowler-cloud/prowler/pull/7562)
- Add new check for AllowList not used in the Connection Filter Policy from service Defender in M365. [(#7492)](https://github.com/prowler-cloud/prowler/pull/7492)
- Add new check for SafeList not enabled in the Connection Filter Policy from service Defender in M365. [(#7492)](https://github.com/prowler-cloud/prowler/pull/7492)
- Add new check for DKIM enabled for service Defender in M365. [(#7485)](https://github.com/prowler-cloud/prowler/pull/7485)
- Add new check `teams_meeting_anonymous_user_start_disabled`. [(#7567)](https://github.com/prowler-cloud/prowler/pull/7567)
- Add new check `teams_meeting_external_lobby_bypass_disabled`. [(#7568)](https://github.com/prowler-cloud/prowler/pull/7568)
- Add new check `teams_meeting_dial_in_lobby_bypass_disabled`. [(#7571)](https://github.com/prowler-cloud/prowler/pull/7571)
- Add new check `teams_meeting_external_control_disabled`. [(#7604)](https://github.com/prowler-cloud/prowler/pull/7604)
- Add new check `teams_meeting_external_chat_disabled`. [(#7605)](https://github.com/prowler-cloud/prowler/pull/7605)
- Add new check `teams_meeting_recording_disabled`. [(#7607)](https://github.com/prowler-cloud/prowler/pull/7607)
- Add new check `teams_meeting_presenters_restricted`. [(#7613)](https://github.com/prowler-cloud/prowler/pull/7613)
- Add new check `teams_security_reporting_enabled`. [(#7614)](https://github.com/prowler-cloud/prowler/pull/7614)
- Add new check `defender_chat_report_policy_configured`. [(#7614)](https://github.com/prowler-cloud/prowler/pull/7614)
- Add new check `teams_meeting_chat_anonymous_users_disabled`. [(#7579)](https://github.com/prowler-cloud/prowler/pull/7579)
- Add Prowler Threat Score Compliance Framework. [(#7603)](https://github.com/prowler-cloud/prowler/pull/7603)
- Add documentation for M365 provider. [(#7622)](https://github.com/prowler-cloud/prowler/pull/7622)
- Add support for m365 provider in Prowler Dashboard. [(#7633)](https://github.com/prowler-cloud/prowler/pull/7633)
- Add new check for Modern Authentication enabled for Exchange Online in M365. [(#7636)](https://github.com/prowler-cloud/prowler/pull/7636)
- Add new check `sharepoint_onedrive_sync_restricted_unmanaged_devices`. [(#7589)](https://github.com/prowler-cloud/prowler/pull/7589)
- Add new check for Additional Storage restricted for Exchange in M365. [(#7638)](https://github.com/prowler-cloud/prowler/pull/7638)
- Add new check for Roles Assignment Policy with no AddIns for Exchange in M365. [(#7644)](https://github.com/prowler-cloud/prowler/pull/7644)
- Add new check for Auditing Mailbox on E3 users is enabled for Exchange in M365. [(#7642)](https://github.com/prowler-cloud/prowler/pull/7642)
- Add new check for SMTP Auth disabled for Exchange in M365. [(#7640)](https://github.com/prowler-cloud/prowler/pull/7640)
- Add new check for MailTips full enabled for Exchange in M365. [(#7637)](https://github.com/prowler-cloud/prowler/pull/7637)
- Add new check for Comprehensive Attachments Filter Applied for Defender in M365. [(#7661)](https://github.com/prowler-cloud/prowler/pull/7661)
- Modified check `exchange_mailbox_properties_auditing_enabled` to make it configurable. [(#7662)](https://github.com/prowler-cloud/prowler/pull/7662)
- Add snapshots to m365 documentation. [(#7673)](https://github.com/prowler-cloud/prowler/pull/7673)
- Add support for static credentials for sending findings to Amazon S3 and AWS Security Hub. [(#7322)](https://github.com/prowler-cloud/prowler/pull/7322)
- Add Prowler ThreatScore for M365 provider. [(#7692)](https://github.com/prowler-cloud/prowler/pull/7692)
- Add Microsoft User and User Credential auth to reports [(#7681)](https://github.com/prowler-cloud/prowler/pull/7681)

### Fixed
- Fix package name location in pyproject.toml while replicating for prowler-cloud. [(#7531)](https://github.com/prowler-cloud/prowler/pull/7531)
- Remove cache in PyPI release action. [(#7532)](https://github.com/prowler-cloud/prowler/pull/7532)
- Add the correct values for logger.info inside iam service. [(#7526)](https://github.com/prowler-cloud/prowler/pull/7526)
- Update S3 bucket naming validation to accept dots. [(#7545)](https://github.com/prowler-cloud/prowler/pull/7545)
- Handle new FlowLog model properties in Azure. [(#7546)](https://github.com/prowler-cloud/prowler/pull/7546)
- Improve compliance and dashboard. [(#7596)](https://github.com/prowler-cloud/prowler/pull/7596)
- Remove invalid parameter `create_file_descriptor`. [(#7600)](https://github.com/prowler-cloud/prowler/pull/7600)
- Remove first empty line in HTML output. [(#7606)](https://github.com/prowler-cloud/prowler/pull/7606)
- Remove empty files in Prowler. [(#7627)](https://github.com/prowler-cloud/prowler/pull/7627)
- Ensure that ContentType in upload_file matches the uploaded file's format. [(#7635)](https://github.com/prowler-cloud/prowler/pull/7635)
- Fix incorrect check inside 4.4.1 requirement for Azure CIS 2.0. [(#7656)](https://github.com/prowler-cloud/prowler/pull/7656)
- Remove muted findings on compliance page from Prowler Dashboard. [(#7683)](https://github.com/prowler-cloud/prowler/pull/7683)
- Remove duplicated findings on compliance page from Prowler Dashboard. [(#7686)](https://github.com/prowler-cloud/prowler/pull/7686)
- Fix incorrect values for Prowler Threatscore compliance LevelOfRisk inside requirements. [(#7667)](https://github.com/prowler-cloud/prowler/pull/7667)

---

## [v5.5.1] (Prowler v5.5.1)

### Fixed
- Add default name to contacts in Azure Defender. [(#7483)](https://github.com/prowler-cloud/prowler/pull/7483)
- Handle projects without ID in GCP. [(#7496)](https://github.com/prowler-cloud/prowler/pull/7496)
- Restore packages location in PyProject. [(#7510)](https://github.com/prowler-cloud/prowler/pull/7510)

---
