# Prowler UI Changelog

All notable changes to the **Prowler UI** are documented in this file.

---

### [v1.5.0] (Prowler v5.5.0 - UNRELEASED)

#### 🚀 Added

- Social login integration with Google and GitHub [(#7218)](https://github.com/prowler-cloud/prowler/pull/7218)
- Added `one-time scan` feature: Adds support for single scan execution. [(#7188)](https://github.com/prowler-cloud/prowler/pull/7188)
- Accepted invitations can no longer be edited. [(#7198)](https://github.com/prowler-cloud/prowler/pull/7198)
- Added download column in scans table to download reports for completed scans. [(#7353)](https://github.com/prowler-cloud/prowler/pull/7353)


#### 🔄 Changed

- Tweak styles for compliance cards. [(#7148)](https://github.com/prowler-cloud/prowler/pull/7148).
- Upgrade Next.js to v14.2.25 to fix a middleware authorization vulnerability. [(#7339)](https://github.com/prowler-cloud/prowler/pull/7339)

---

### [v1.4.0] (Prowler v5.4.0)

#### 🚀 Added

- Added `exports` feature: Users can now download artifacts via a new button. [(#7006)](https://github.com/prowler-cloud/prowler/pull/7006)
- New sidebar with nested menus and integrated mobile navigation. [(#7018)](https://github.com/prowler-cloud/prowler/pull/7018)
- Added animation for scan execution progress—it now updates automatically.[(#6972)](https://github.com/prowler-cloud/prowler/pull/6972)
- Add `status_extended` attribute to finding details. [(#6997)](https://github.com/prowler-cloud/prowler/pull/6997)
- Add `Prowler version` to the sidebar. [(#7086)](https://github.com/prowler-cloud/prowler/pull/7086)
  
#### 🔄 Changed

- New compliance dropdown. [(#7118)](https://github.com/prowler-cloud/prowler/pull/7118).
  
#### 🐞 Fixes

- Revalidate the page when a role is deleted. [(#6976)](https://github.com/prowler-cloud/prowler/pull/6976)
- Allows removing group visibility when creating a role. [(#7088)](https://github.com/prowler-cloud/prowler/pull/7088)
- Displays correct error messages when deleting a user. [(#7089)](https://github.com/prowler-cloud/prowler/pull/7089)
- Updated label: *"Select a scan job"* → *"Select a cloud provider"*. [(#7107)](https://github.com/prowler-cloud/prowler/pull/7107)
- Display uid if alias is missing when creating a group. [(#7137)](https://github.com/prowler-cloud/prowler/pull/7137)

---

### [v1.3.0] (Prowler v5.3.0)

#### 🚀 Added

- Findings endpoints now require at least one date filter [(#6864)](https://github.com/prowler-cloud/prowler/pull/6864).

#### 🔄 Changed

- Scans now appear immediately after launch. [(#6791)](https://github.com/prowler-cloud/prowler/pull/6791).
- Improved sign-in and sign-up forms. [(#6813)](https://github.com/prowler-cloud/prowler/pull/6813).

---

### [v1.2.0] (Prowler v5.2.0)

#### 🚀 Added

- `First seen` field included in finding details. [(#6575)](https://github.com/prowler-cloud/prowler/pull/6575)

#### 🔄 Changed

- Completely redesigned finding details layout. [(#6575)](https://github.com/prowler-cloud/prowler/pull/6575)
- Completely redesigned scan details layout.[(#6665)](https://github.com/prowler-cloud/prowler/pull/6665)
- Simplified provider setup: reduced from 4 to 3 steps. Successful connection now triggers an animation before redirecting to `/scans`. [(#6665)](https://github.com/prowler-cloud/prowler/pull/6665)

---
