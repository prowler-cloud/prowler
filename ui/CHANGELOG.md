# Prowler UI Changelog

All notable changes to the **Prowler UI** are documented in this file.

## [1.12.1] (Prowler v5.12.1)

### 🚀 Added

- `Prowler Hub` menu item with tooltip [(#8692)] (https://github.com/prowler-cloud/prowler/pull/8692)
- Copy link button to finding detail page [(#8685)] (https://github.com/prowler-cloud/prowler/pull/8685)

## [1.12.0] (Prowler v5.12.0)

### 🚀 Added

- Jira integration[(#8640)](https://github.com/prowler-cloud/prowler/pull/8640),[(#8649)](https://github.com/prowler-cloud/prowler/pull/8649)

### 🔄 Changed

- Overview chart "Findings by Severity" now shows only failing findings (defaults to `status=FAIL`) and chart links open the Findings page pre-filtered to fails per severity [(#8186)](https://github.com/prowler-cloud/prowler/pull/8186)
- Handle API responses and errors consistently across the app [(#8621)](https://github.com/prowler-cloud/prowler/pull/8621)
- No-permission message on the scan page [(#8624)](https://github.com/prowler-cloud/prowler/pull/8624)
- Markdown rendering in finding details page [(#8604)](https://github.com/prowler-cloud/prowler/pull/8604)

### 🐞 Fixed

- Scan page shows NoProvidersAdded when no providers [(#8626)](https://github.com/prowler-cloud/prowler/pull/8626)
- XML field in SAML configuration form validation [(#8638)](https://github.com/prowler-cloud/prowler/pull/8638)
- Social login buttons in sign-up page [(#8673)](https://github.com/prowler-cloud/prowler/pull/8673)

---

## [1.11.0] (Prowler v5.11.0)

### 🚀 Added

- Security Hub integration [(#8552)](https://github.com/prowler-cloud/prowler/pull/8552)
- `Cloud Provider` type filter to providers page [(#8473)](https://github.com/prowler-cloud/prowler/pull/8473)
- New menu item under Configuration section for quick access to the Mutelist [(#8444)](https://github.com/prowler-cloud/prowler/pull/8444)
- Resource agent to Lighthouse for querying resource information [(#8509)](https://github.com/prowler-cloud/prowler/pull/8509)
- Lighthouse support for OpenAI GPT-5 [(#8527)](https://github.com/prowler-cloud/prowler/pull/8527)
- Link to the configured S3 bucket and folder in each integration [(#8554)](https://github.com/prowler-cloud/prowler/pull/8554)

### 🔄 Changed

- Disable `See Compliance` button until scan completes [(#8487)](https://github.com/prowler-cloud/prowler/pull/8487)
- Provider connection filter now shows "Connected/Disconnected" instead of "true/false" for better UX [(#8520)](https://github.com/prowler-cloud/prowler/pull/8520)
- Provider Uid filter on scan page to list all UIDs regardless of connection status [(#8375)] (https://github.com/prowler-cloud/prowler/pull/8375)

### 🐞 Fixed

- Default value inside credentials form in AWS Provider add workflow properly set [(#8553)](https://github.com/prowler-cloud/prowler/pull/8553)
- Auth callback route checking working as expected [(#8556)](https://github.com/prowler-cloud/prowler/pull/8556)
- DataTable column headers set to single-line [(#8480)](https://github.com/prowler-cloud/prowler/pull/8480)

---

## [1.10.2] (Prowler v5.10.3)

### 🐞 Fixed

- Lighthouse using default config instead of backend config [(#8546)](https://github.com/prowler-cloud/prowler/pull/8546)

---

## [1.10.1] (Prowler v5.10.1)

### 🐞 Fixed

- Field for `Assume Role` in AWS role credentials form shown again [(#8484)](https://github.com/prowler-cloud/prowler/pull/8484)
- `GitHub` submenu to High Risk Findings [(#8488)](https://github.com/prowler-cloud/prowler/pull/8488)
- Improved Overview chart `Findings by Severity` spacing [(#8491)](https://github.com/prowler-cloud/prowler/pull/8491)

## [1.10.0] (Prowler v5.10.0)

### 🚀 Added

- Lighthouse banner [(#8259)](https://github.com/prowler-cloud/prowler/pull/8259)
- Amazon AWS S3 integration [(#8391)](https://github.com/prowler-cloud/prowler/pull/8391)
- Github provider support [(#8405)](https://github.com/prowler-cloud/prowler/pull/8405)
- XML validation for SAML metadata in the UI [(#8429)](https://github.com/prowler-cloud/prowler/pull/8429)
- Default Mutelist placeholder in the UI [(#8455)](https://github.com/prowler-cloud/prowler/pull/8455)
- Help link in the SAML configuration modal [(#8461)](https://github.com/prowler-cloud/prowler/pull/8461)

### 🔄 Changed

- Rename `Memberships` to `Organization` in the sidebar [(#8415)](https://github.com/prowler-cloud/prowler/pull/8415)

### 🐞 Fixed

- Display error messages and allow editing last message in Lighthouse [(#8358)](https://github.com/prowler-cloud/prowler/pull/8358)

### ❌ Removed

- Removed `Browse all resources` from the sidebar, sidebar now shows a single `Resources` entry [(#8418)](https://github.com/prowler-cloud/prowler/pull/8418)
- Removed `Misconfigurations` from the `Top Failed Findings` section in the sidebar [(#8426)](https://github.com/prowler-cloud/prowler/pull/8426)

---

## [v1.9.0] (Prowler v5.9.0)

### 🚀 Added

- Mutelist configuration form [(#8190)](https://github.com/prowler-cloud/prowler/pull/8190)
- SAML login integration [(#8203)](https://github.com/prowler-cloud/prowler/pull/8203)
- Resource view [(#7760)](https://github.com/prowler-cloud/prowler/pull/7760)
- Navigation link in Scans view to access Compliance Overview [(#8251)](https://github.com/prowler-cloud/prowler/pull/8251)
- Status column for findings table in the Compliance Detail view [(#8244)](https://github.com/prowler-cloud/prowler/pull/8244)
- Allow to restrict routes access based on user permissions [(#8287)](https://github.com/prowler-cloud/prowler/pull/8287)
- Max character limit validation for Scan label [(#8319)](https://github.com/prowler-cloud/prowler/pull/8319)

### 🔐 Security

- Enhanced password validation to enforce 12+ character passwords with special characters, uppercase, lowercase, and numbers [(#8225)](https://github.com/prowler-cloud/prowler/pull/8225)

### 🔄 Changed

- Upgrade to Next.js 14.2.30 and lock TypeScript to 5.5.4 for ESLint compatibility [(#8189)](https://github.com/prowler-cloud/prowler/pull/8189)
- Improved active step highlighting and updated step titles and descriptions in the Cloud Provider credentials update flow [(#8303)](https://github.com/prowler-cloud/prowler/pull/8303)
- Refactored all existing links across the app to use new custom-link component for consistent styling [(#8341)](https://github.com/prowler-cloud/prowler/pull/8341)

### 🐞 Fixed

- Error message when launching a scan if user has no permissions [(#8280)](https://github.com/prowler-cloud/prowler/pull/8280)
- Include compliance in the download button tooltip [(#8307)](https://github.com/prowler-cloud/prowler/pull/8307)
- Redirection and error handling issues after deleting a provider groups [(#8389)](https://github.com/prowler-cloud/prowler/pull/8389)

---

## [v1.8.1] (Prowler 5.8.1)

### 🔄 Changed

- Latest new failed findings now use `GET /findings/latest` [(#8219)](https://github.com/prowler-cloud/prowler/pull/8219)

### ❌ Removed

- Validation of the provider's secret type during updates [(#8197)](https://github.com/prowler-cloud/prowler/pull/8197)

---

## [v1.8.0] (Prowler v5.8.0)

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
- Compliance detail view: ProwlerThreatScore [(#7979)](https://github.com/prowler-cloud/prowler/pull/7979)
- Compliance detail view: Generic (rest of the compliances) [(#7990)](https://github.com/prowler-cloud/prowler/pull/7990)
- Compliance detail view: MITRE ATTACK [(#8002)](https://github.com/prowler-cloud/prowler/pull/8002)
- Improve `Scan ID` filter by adding more context and enhancing the UI/UX [(#8046)](https://github.com/prowler-cloud/prowler/pull/8046)
- Lighthouse chat interface [(#7878)](https://github.com/prowler-cloud/prowler/pull/7878)
- Google Tag Manager integration [(#8058)](https://github.com/prowler-cloud/prowler/pull/8058)

### 🔄 Changed

- `Provider UID` filter to scans page [(#7820)](https://github.com/prowler-cloud/prowler/pull/7820)
- Aligned Next.js version to `v14.2.29` across Prowler and Cloud environments for consistency and improved maintainability [(#7962)](https://github.com/prowler-cloud/prowler/pull/7962)
- Refactor credentials forms with reusable components and error handling [(#7988)](https://github.com/prowler-cloud/prowler/pull/7988)
- Updated the provider details section in Scan and Findings detail pages [(#7968)](https://github.com/prowler-cloud/prowler/pull/7968)
- Make user and password fields optional but mutually required for M365 cloud provider [(#8044)](https://github.com/prowler-cloud/prowler/pull/8044)
- Improve filter behaviour and relationships between filters in findings page [(#8046)](https://github.com/prowler-cloud/prowler/pull/8046)
- Set filters panel to be always open by default [(#8085)](https://github.com/prowler-cloud/prowler/pull/8085)
- Updated "Sign in"/"Sign up" capitalization for consistency [(#8136)](https://github.com/prowler-cloud/prowler/pull/8136)
- Duplicate API base URL as an env var to make it accessible in client components [(#8131)](https://github.com/prowler-cloud/prowler/pull/8131)

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

### ❌ Removed

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
