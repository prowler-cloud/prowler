# Registry UI Validation

The consolidated implementation provides Registry installation → Providers → account details → schema-driven credentials → explicit connection confirmation → scan launch. Registry requires `manage_registry` and its feature flags, independently of billing. Provider account creation and scans retain their existing permissions.

## Automated Evidence

Validation after review fixes on September 9, 2026:

| Check                           | Result                                                                                   |
| ------------------------------- | ---------------------------------------------------------------------------------------- |
| `pnpm run test:unit`            | 475 files, 3,511 tests passed                                                            |
| `pnpm run test:integration`     | 11 files, 253 browser integration tests passed                                           |
| `pnpm run test:e2e:registry`    | 10 passed; 23 excluded because each scenario runs only in its designated runtime profile |
| `pnpm run typecheck`            | Passed                                                                                   |
| `pnpm run lint:check`           | Passed; excluded the unrelated `.claude/` checkout                                       |
| Prettier check on changed files | Passed                                                                                   |
| `pnpm run build`                | Passed                                                                                   |
| `pnpm run tour:check`           | Six tours and 19 anchors checked                                                         |

The Registry browser suite includes regressions for replacing a rejected key, disabling every Add button during an installation, refreshing an expired owner image, and confirming credential state and collections once. Unit tests cover late completion after the dialog deadline and a single shared failure result when catalog refresh fails. The three removed browser test files covered only the global animation changes withdrawn from this PR.

The test scope review removed 29 net cases and 614 lines across nine test files. Browser tests for pixel spacing, icon classes, avatar internals, and repeated provider layouts were removed or consolidated. Duplicate model, credential-completion, static-label, and environment-parser cases were also pruned. Assertions for pending controls, write-only keys, accessible provider names, single confirmation, and non-persisted eligibility remain in broader behavioral tests. Both first-key and replacement validation now explicitly cover an unsettled task. Permission boundaries, schema validation, recovery, and the controlled E2E scenarios remain covered.

The controlled E2E uses real Next.js servers, authentication, proxy, Server Actions, task polling, and browser storage against a synthetic HTTP API. It covers Registry enabled with billing disabled, Registry disabled, Cloud disabled, permission revocation, installation and removal, account preservation, the provider wizard, a completed scan, and recovery after a hard reload. It does not validate real Registry or provider services.

The reload regression aborts a pending Server Action request. The shared watcher preserves the backend task ID on page hide, resumes it after reload or browser history restoration, and emits one confirmation after reading tenant membership. Pending metadata contains artifact identifiers or the prior-credential flag, never submitted keys.

See [the scenario catalog](registry.md) and [the Add Provider tour report](add-provider-tour-report.md).

## Registry Environment Configuration

Set these runtime variables on the UI service to match the Registry used by the backend:

| Variable                | Purpose                                                                                                    | Development Example                      |
| ----------------------- | ---------------------------------------------------------------------------------------------------------- | ---------------------------------------- |
| `UI_REGISTRY_URL`       | Public Registry website or key-management page. Supplies the help link and permits images from its origin. | `https://registry.dev.prowler.com`       |
| `UI_REGISTRY_MEDIA_URL` | Registry media service. Only its HTTP(S) origin is added to `img-src`.                                     | `https://media.registry.dev.prowler.com` |

For production, use `https://registry.prowler.com` and `https://media.registry.prowler.com`. For a private Registry, use its website and media service URLs. These settings do not change the backend's Registry API endpoint. Keep both services aligned in deployment configuration: the current backend contract does not expose its Registry website URL to the UI.

The help link is hidden when its URL is missing or invalid, so the UI cannot send a private Registry user to production by default. URLs containing credentials, non-HTTP schemes, or CSP separators are rejected. Unconfigured external images fall back to the owner initial.

Acceptance profiles and fixture servers live in `playwright.registry.config.ts`, with common defaults in `playwright.base.ts`. The existing `pnpm run test:e2e:registry` command selects that configuration. The general Playwright configuration runs the ordinary suites without Registry fixtures.

Credential validation has one completion path shared by active execution and reload recovery. After task settlement, it reads credential status once and collections once; the returned result drives both dialog state and notification. A deadline releases the form without reporting success; the same completion continues in the background.

## Screenshots

These captures contain synthetic fixture data. The credential form is empty in its screenshot.

| View           | Evidence                                                                |
| -------------- | ----------------------------------------------------------------------- |
| Desktop, dark  | [Catalog](evidence/registry-catalog-desktop-dark.png)                   |
| Desktop, light | [Catalog](evidence/registry-catalog-desktop-light.png)                  |
| Tablet, light  | [Catalog](evidence/registry-catalog-tablet-light.png)                   |
| Mobile, dark   | [Catalog](evidence/registry-catalog-mobile-dark.png)                    |
| Add Provider   | [Registry option](evidence/registry-provider-selector.png)              |
| Credentials    | [Schema form](evidence/registry-provider-credentials.png)               |
| Scans          | [Completed fixture scan](evidence/registry-provider-scan-completed.png) |

Run `pnpm run test:e2e:registry` to regenerate screenshot attachments in the Playwright output directory.

## Live Integration Status

Live acceptance is incomplete. The isolated backend runs `chain/14-dynamic-provider-scans` with Registry mode `official`, development Registry API/index/media URLs, and billing disabled. The local UI uses `UI_CLOUD_ENABLED=true`, `UI_REGISTRY_ENABLED=true`, `CLOUD_BILLING_ENABLED=false`, and the local API. Distribution defaults remain disabled.

The native macOS Celery worker repeatedly exited with `SIGSEGV` during key validation. Restarting this development worker with `--pool=solo --concurrency=1` allowed the queued validation to finish. The development Registry then rejected the submitted key with HTTP 401. No backend source changes were made.

A valid key for the development Registry and credentials for an external test provider must be entered through the local UI to complete the real catalog, install, account, credential, connection, and scan checks. The PR remains a draft pending that evidence; automated fixture results do not satisfy live acceptance.
