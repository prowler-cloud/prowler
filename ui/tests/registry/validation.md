# Registry UI Validation

The consolidated implementation provides Registry installation → Providers → account details → schema-driven credentials → explicit connection confirmation → scan launch. Registry requires `manage_registry` and its feature flags, independently of billing. Provider account creation and scans retain their existing permissions.

## Automated Evidence

Validation on September 8, 2026:

| Check                        | Result                                                                                   |
| ---------------------------- | ---------------------------------------------------------------------------------------- |
| `pnpm run test:unit`         | 474 files, 3,512 tests passed                                                            |
| `pnpm run test:integration`  | 14 files, 274 browser integration tests passed                                           |
| `pnpm run test:e2e:registry` | 10 passed; 23 excluded because each scenario runs only in its designated runtime profile |
| `pnpm run typecheck`         | Passed                                                                                   |
| `pnpm run lint:check`        | Passed with one existing native image warning                                            |
| `pnpm run format:check`      | Passed                                                                                   |
| `CI=true pnpm run build`     | Passed                                                                                   |
| `pnpm run tour:check`        | Six tours and 19 anchors checked                                                         |

The controlled E2E uses real Next.js servers, authentication, proxy, Server Actions, task polling, and browser storage against a synthetic HTTP API. It covers Registry enabled with billing disabled, Registry disabled, Cloud disabled, permission revocation, installation and removal, account preservation, the provider wizard, a completed scan, and recovery after a hard reload. It does not validate real Registry or provider services.

The reload regression aborts a pending Server Action request. The shared watcher preserves the backend task ID on page hide, resumes it after reload or browser history restoration, and emits one confirmation after reading tenant membership. Pending metadata contains identifiers only.

See [the scenario catalog](registry.md) and [the Add Provider tour report](add-provider-tour-report.md).

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
