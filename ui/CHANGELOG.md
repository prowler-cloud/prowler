# Prowler UI Changelog

All notable changes to the **Prowler UI** are documented in this file.

## [v1.8.0] (Prowler v5.8.0) – Not released

### 🚀 Added

- New profile page with details about the user and their roles [(#7780)](https://github.com/prowler-cloud/prowler/pull/7780)
- Improved `SnippetChip` component and show resource name in new findings table [(#7813)](https://github.com/prowler-cloud/prowler/pull/7813)
- Possibility to edit the organization name [(#7829)](https://github.com/prowler-cloud/prowler/pull/7829)
- GCP credential method (Account Service Key) [(#7872)](https://github.com/prowler-cloud/prowler/pull/7872)
- Compliance detail view: ENS [(#7853)](https://github.com/prowler-cloud/prowler/pull/7853)
- Compliance detail view: ISO [(#7897)](https://github.com/prowler-cloud/prowler/pull/7897)
- Compliance detail view: CIS [(#7913)](https://github.com/prowler-cloud/prowler/pull/7913)
- Compliance detail view: AWS Well-Architected Framework [(#7925)](https://github.com/prowler-cloud/prowler/pull/7925)
- Compliance detail view: KISA [(#7965)](https://github.com/prowler-cloud/prowler/pull/7965)
- Compliance detail view: ProwlerThreatScore [(#7966)](https://github.com/prowler-cloud/prowler/pull/7966)
- Compliance detail view: Generic (rest of the compliances) [(#7990)](https://github.com/prowler-cloud/prowler/pull/7990)
- Compliance detail view: MITRE ATTACK [(#8002)](https://github.com/prowler-cloud/prowler/pull/8002)
- Improve `Scan ID` filter by adding more context and enhancing the UI/UX [(#7979)](https://github.com/prowler-cloud/prowler/pull/7979)
- Lighthouse chat interface [(#7878)](https://github.com/prowler-cloud/prowler/pull/7878)
- Google Tag Manager integration [(#8058)](https://github.com/prowler-cloud/prowler/pull/8058)
- SAML login integration [(#8094)](https://github.com/prowler-cloud/prowler/pull/8094)

### 🔄 Changed

- `Provider UID` filter to scans page [(#7820)](https://github.com/prowler-cloud/prowler/pull/7820)
- Aligned Next.js version to `v14.2.29` across Prowler and Cloud environments for consistency and improved maintainability [(#7962)](https://github.com/prowler-cloud/prowler/pull/7962)
- Refactor credentials forms with reusable components and error handling [(#7988)](https://github.com/prowler-cloud/prowler/pull/7988)
- Updated the provider details section in Scan and Findings detail pages [(#7968)](https://github.com/prowler-cloud/prowler/pull/7968)
- Make user and password fields optional but mutually required for M365 cloud provider [(#8044)](https://github.com/prowler-cloud/prowler/pull/8044)
- Improve filter behaviour and relationships between filters in findings page [(#8046)](https://github.com/prowler-cloud/prowler/pull/8046)
- Set filters panel to be always open by default [(#8085)](https://github.com/prowler-cloud/prowler/pull/8085)

### 🐞 Fixed

- Sync between filter buttons and URL when filters change [(#7928)](https://github.com/prowler-cloud/prowler/pull/7928)
- Improve heatmap perfomance [(#7934)](https://github.com/prowler-cloud/prowler/pull/7934)
- SelectScanProvider warning fixed with empty alias [(#7998)](https://github.com/prowler-cloud/prowler/pull/7998)
- Prevent console warnings for accessibility and SVG[(#8019)](https://github.com/prowler-cloud/prowler/pull/8019)

---

## [v1.7.3] (Prowler v5.7.3)

### 🐞 Fixed

- Encrypted password typo in `formSchemas` [(#7828)](https://github.com/prowler-cloud/prowler/pull/7828)

---

## [v1.7.2] (Prowler v5.7.2)

### 🐞 Fixed

- Download report behaviour updated to show feedback based on API response [(#7758)](https://github.com/prowler-cloud/prowler/pull/7758)
- Missing KISA and ProwlerThreat icons added to the compliance page [(#7860)(https://github.com/prowler-cloud/prowler/pull/7860)]
- Retrieve more than 10 scans in /compliance page [(#7865)](https://github.com/prowler-cloud/prowler/pull/7865)
- Improve CustomDropdownFilter component [(#7868)(https://github.com/prowler-cloud/prowler/pull/7868)]

---

## [v1.7.1] (Prowler v5.7.1)

### 🐞 Fixed

- Validation to AWS IAM role [(#7787)](https://github.com/prowler-cloud/prowler/pull/7787)
- Tweak some wording for consistency throughout the app [(#7794)](https://github.com/prowler-cloud/prowler/pull/7794)
- Retrieve more than 10 providers in /scans, /manage-groups and /findings pages [(#7793)](https://github.com/prowler-cloud/prowler/pull/7793)

---

## [v1.7.0] (Prowler v5.7.0)

### 🚀 Added

- Chart to show the split between passed and failed findings [(#7680)](https://github.com/prowler-cloud/prowler/pull/7680)
- `Accordion` component [(#7700)](https://github.com/prowler-cloud/prowler/pull/7700)
- Improve `Provider UID` filter by adding more context and enhancing the UI/UX [(#7741)](https://github.com/prowler-cloud/prowler/pull/7741)
- AWS CloudFormation Quick Link to the IAM Role credentials step [(#7735)](https://github.com/prowler-cloud/prowler/pull/7735)
  – Use `getLatestFindings` on findings page when no scan or date filters are applied [(#7756)](https://github.com/prowler-cloud/prowler/pull/7756)

### 🐞 Fixed

- Form validation in launch scan workflow [(#7693)](https://github.com/prowler-cloud/prowler/pull/7693)
- Moved ProviderType to a shared types file and replaced all occurrences across the codebase [(#7710)](https://github.com/prowler-cloud/prowler/pull/7710)
- Added filter to retrieve only connected providers on the scan page [(#7723)](https://github.com/prowler-cloud/prowler/pull/7723)

### Removed

- Alias if not added from findings detail page [(#7751)](https://github.com/prowler-cloud/prowler/pull/7751)

---

## [v1.6.0] (Prowler v5.6.0)

### 🚀 Added

- Support for the `M365` Cloud Provider [(#7590)](https://github.com/prowler-cloud/prowler/pull/7590)
- Option to customize the number of items displayed per table page [(#7634)](https://github.com/prowler-cloud/prowler/pull/7634)
- Delta attribute in findings detail view [(#7654)](https://github.com/prowler-cloud/prowler/pull/7654)
- Delta indicator in new findings table [(#7676)](https://github.com/prowler-cloud/prowler/pull/7676)
- Button to download the CSV report in compliance card [(#7665)](https://github.com/prowler-cloud/prowler/pull/7665)
- Show loading state while checking provider connection [(#7669)](https://github.com/prowler-cloud/prowler/pull/7669)

### 🔄 Changed

- Finding URLs now include the ID, allowing them to be shared within the organization [(#7654)](https://github.com/prowler-cloud/prowler/pull/7654)
- Show Add/Update credentials depending on whether a secret is already set or not [(#7669)](https://github.com/prowler-cloud/prowler/pull/7669)

### 🐞 Fixed

- Set a default session duration when configuring an AWS Cloud Provider using a role [(#7639)](https://github.com/prowler-cloud/prowler/pull/7639)
- Error about page number persistence when filters change [(#7655)](https://github.com/prowler-cloud/prowler/pull/7655)

---

## [v1.5.0] (Prowler v5.5.0)

### 🚀 Added

- Social login integration with Google and GitHub [(#7218)](https://github.com/prowler-cloud/prowler/pull/7218)
- `one-time scan` feature: Adds support for single scan execution [(#7188)](https://github.com/prowler-cloud/prowler/pull/7188)
- Accepted invitations can no longer be edited [(#7198)](https://github.com/prowler-cloud/prowler/pull/7198)
- Download column in scans table to download reports for completed scans [(#7353)](https://github.com/prowler-cloud/prowler/pull/7353)
- Show muted icon when a finding is muted [(#7378)](https://github.com/prowler-cloud/prowler/pull/7378)
- Static status icon with link to service status page [(#7468)](https://github.com/prowler-cloud/prowler/pull/7468)

### 🔄 Changed

- Tweak styles for compliance cards [(#7148)](https://github.com/prowler-cloud/prowler/pull/7148)
- Upgrade Next.js to v14.2.25 to fix a middleware authorization vulnerability [(#7339)](https://github.com/prowler-cloud/prowler/pull/7339)
- Apply default filter to show only failed items when coming from scan table [(#7356)](https://github.com/prowler-cloud/prowler/pull/7356)
- Fix link behavior in scan cards: only disable "View Findings" when scan is not completed or executing [(#7368)](https://github.com/prowler-cloud/prowler/pull/7368)

---

## [v1.4.0] (Prowler v5.4.0)

### 🚀 Added

- `exports` feature: Users can now download artifacts via a new button [(#7006)](https://github.com/prowler-cloud/prowler/pull/7006)
- New sidebar with nested menus and integrated mobile navigation [(#7018)](https://github.com/prowler-cloud/prowler/pull/7018)
- Animation for scan execution progress—it now updates automatically.[(#6972)](https://github.com/prowler-cloud/prowler/pull/6972)
- `status_extended` attribute to finding details [(#6997)](https://github.com/prowler-cloud/prowler/pull/6997)
- `Prowler version` to the sidebar [(#7086)](https://github.com/prowler-cloud/prowler/pull/7086)

### 🔄 Changed

- New compliance dropdown [(#7118)](https://github.com/prowler-cloud/prowler/pull/7118)

### 🐞 Fixed

- Revalidate the page when a role is deleted [(#6976)](https://github.com/prowler-cloud/prowler/pull/6976)
- Allows removing group visibility when creating a role [(#7088)](https://github.com/prowler-cloud/prowler/pull/7088)
- Displays correct error messages when deleting a user [(#7089)](https://github.com/prowler-cloud/prowler/pull/7089)
- Updated label: _"Select a scan job"_ → _"Select a cloud provider"_ [(#7107)](https://github.com/prowler-cloud/prowler/pull/7107)
- Display uid if alias is missing when creating a group [(#7137)](https://github.com/prowler-cloud/prowler/pull/7137)

---

## [v1.3.0] (Prowler v5.3.0)

### 🚀 Added

- Findings endpoints now require at least one date filter [(#6864)](https://github.com/prowler-cloud/prowler/pull/6864)

### 🔄 Changed

- Scans now appear immediately after launch [(#6791)](https://github.com/prowler-cloud/prowler/pull/6791)
- Improved sign-in and sign-up forms [(#6813)](https://github.com/prowler-cloud/prowler/pull/6813)

---

## [v1.2.0] (Prowler v5.2.0)

### 🚀 Added

- `First seen` field included in finding details [(#6575)](https://github.com/prowler-cloud/prowler/pull/6575)

### 🔄 Changed

- Completely redesigned finding details layout [(#6575)](https://github.com/prowler-cloud/prowler/pull/6575)
- Completely redesigned scan details layout [(#6665)](https://github.com/prowler-cloud/prowler/pull/6665)
- Simplified provider setup: reduced from 4 to 3 steps Successful connection now triggers an animation before redirecting to `/scans` [(#6665)](https://github.com/prowler-cloud/prowler/pull/6665)

---
