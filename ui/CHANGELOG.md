# Prowler UI Changelog

All notable changes to the **Prowler UI** are documented in this file.

---

## [v1.6.0] (Prowler v5.6.0)

### 🚀 Added

- Support for the `M365` Cloud Provider. [(#7590)](https://github.com/prowler-cloud/prowler/pull/7590)
- Added option to customize the number of items displayed per table page. [(#7634)](https://github.com/prowler-cloud/prowler/pull/7634)
- Add delta attribute in findings detail view. [(#7654)](https://github.com/prowler-cloud/prowler/pull/7654)
- Add delta indicator in new findings table. [(#7676)](https://github.com/prowler-cloud/prowler/pull/7676)
- Add a button to download the CSV report in compliance card. [(#7665)](https://github.com/prowler-cloud/prowler/pull/7665)
- Show loading state while checking provider connection. [(#7669)](https://github.com/prowler-cloud/prowler/pull/7669)
- Add a new chart to show the split between passed and failed findings. [(#7680)](https://github.com/prowler-cloud/prowler/pull/7680)

### 🔄 Changed

- Finding URLs now include the ID, allowing them to be shared within the organization. [(#7654)](https://github.com/prowler-cloud/prowler/pull/7654)
- Show Add/Update credentials depending on whether a secret is already set or not. [(#7669)](https://github.com/prowler-cloud/prowler/pull/7669)

### 🐞 Fixes

- Set a default session duration when configuring an AWS Cloud Provider using a role. [(#7639)](https://github.com/prowler-cloud/prowler/pull/7639)
- Error about page number persistence when filters change. [(#7655)](https://github.com/prowler-cloud/prowler/pull/7655)

---

## [v1.5.0] (Prowler v5.5.0)

### 🚀 Added

- Social login integration with Google and GitHub [(#7218)](https://github.com/prowler-cloud/prowler/pull/7218)
- Added `one-time scan` feature: Adds support for single scan execution. [(#7188)](https://github.com/prowler-cloud/prowler/pull/7188)
- Accepted invitations can no longer be edited. [(#7198)](https://github.com/prowler-cloud/prowler/pull/7198)
- Added download column in scans table to download reports for completed scans. [(#7353)](https://github.com/prowler-cloud/prowler/pull/7353)
- Show muted icon when a finding is muted. [(#7378)](https://github.com/prowler-cloud/prowler/pull/7378)
- Added static status icon with link to service status page. [(#7468)](https://github.com/prowler-cloud/prowler/pull/7468)

### 🔄 Changed

- Tweak styles for compliance cards. [(#7148)](https://github.com/prowler-cloud/prowler/pull/7148).
- Upgrade Next.js to v14.2.25 to fix a middleware authorization vulnerability. [(#7339)](https://github.com/prowler-cloud/prowler/pull/7339)
- Apply default filter to show only failed items when coming from scan table. [(#7356)](https://github.com/prowler-cloud/prowler/pull/7356)
- Fix link behavior in scan cards: only disable "View Findings" when scan is not completed or executing. [(#7368)](https://github.com/prowler-cloud/prowler/pull/7368)

---

## [v1.4.0] (Prowler v5.4.0)

### 🚀 Added

- Added `exports` feature: Users can now download artifacts via a new button. [(#7006)](https://github.com/prowler-cloud/prowler/pull/7006)
- New sidebar with nested menus and integrated mobile navigation. [(#7018)](https://github.com/prowler-cloud/prowler/pull/7018)
- Added animation for scan execution progress—it now updates automatically.[(#6972)](https://github.com/prowler-cloud/prowler/pull/6972)
- Add `status_extended` attribute to finding details. [(#6997)](https://github.com/prowler-cloud/prowler/pull/6997)
- Add `Prowler version` to the sidebar. [(#7086)](https://github.com/prowler-cloud/prowler/pull/7086)

### 🔄 Changed

- New compliance dropdown. [(#7118)](https://github.com/prowler-cloud/prowler/pull/7118).

### 🐞 Fixes

- Revalidate the page when a role is deleted. [(#6976)](https://github.com/prowler-cloud/prowler/pull/6976)
- Allows removing group visibility when creating a role. [(#7088)](https://github.com/prowler-cloud/prowler/pull/7088)
- Displays correct error messages when deleting a user. [(#7089)](https://github.com/prowler-cloud/prowler/pull/7089)
- Updated label: *"Select a scan job"* → *"Select a cloud provider"*. [(#7107)](https://github.com/prowler-cloud/prowler/pull/7107)
- Display uid if alias is missing when creating a group. [(#7137)](https://github.com/prowler-cloud/prowler/pull/7137)

---

## [v1.3.0] (Prowler v5.3.0)

### 🚀 Added

- Findings endpoints now require at least one date filter [(#6864)](https://github.com/prowler-cloud/prowler/pull/6864).

### 🔄 Changed

- Scans now appear immediately after launch. [(#6791)](https://github.com/prowler-cloud/prowler/pull/6791).
- Improved sign-in and sign-up forms. [(#6813)](https://github.com/prowler-cloud/prowler/pull/6813).

---

## [v1.2.0] (Prowler v5.2.0)

### 🚀 Added

- `First seen` field included in finding details. [(#6575)](https://github.com/prowler-cloud/prowler/pull/6575)

### 🔄 Changed

- Completely redesigned finding details layout. [(#6575)](https://github.com/prowler-cloud/prowler/pull/6575)
- Completely redesigned scan details layout.[(#6665)](https://github.com/prowler-cloud/prowler/pull/6665)
- Simplified provider setup: reduced from 4 to 3 steps. Successful connection now triggers an animation before redirecting to `/scans`. [(#6665)](https://github.com/prowler-cloud/prowler/pull/6665)

---
