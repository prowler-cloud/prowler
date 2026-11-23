# Prowler Realtime

Read this before changing anything under `app/(prowler)/realtime/`. General UI rules live in `ui/AGENTS.md`.

## What It Is

Realtime reads AWS CloudTrail events, raises detections, and can fix (and revert) AWS resources. It is a Prowler Cloud feature: both pages call `notFound()` unless `isCloud()`, and only AWS providers are offered (`_lib/load.ts`).

## Owner Map

| Concern                                        | Owner                                                                                                              |
| ---------------------------------------------- | ------------------------------------------------------------------------------------------------------------------ |
| Dashboard page and tabs (`?tab=`)              | `page.tsx`, `_components/dashboard/`, `_lib/routes.ts` (`REALTIME_TAB`, `REALTIME_PARAM`)                          |
| Setup and policy                               | `configuration/page.tsx`, `_components/configuration/`, `_lib/setup.ts` (step order mirrors the API's setup steps) |
| One tab per folder                             | `_components/{overview,detections,remediation,stream,findings,cost}/`                                              |
| Every API call                                 | `_actions/realtime.ts`, through the private `call()` helper                                                        |
| JSON:API → view models                         | `_actions/realtime.adapter.ts`, types in `_types/`                                                                 |
| Per-request read shared by header and Overview | `_lib/cached.ts` (`React.cache`)                                                                                   |

## Rules

- **All requests go through `call()` in `_actions/realtime.ts`.** It allows only known path shapes and plain query values (SSRF guard), adds `getAuthHeaders()`, and treats 409 (AWS refused a revert) and 503 (data store not configured) as answers the UI explains, not server errors. Add a new endpoint as a new exported action on top of `call()`, never with a raw `fetch`.
- **Sample data while there is no policy.** `isRealtimeDemo(policy)` (`_lib/demo.ts`) switches the dashboard to API demo data until the account has a policy; a paused policy still shows real history. Write controls render disabled with `DEMO_TOOLTIP` on demo data.
- **Permission.** `canManageRealtime()` reads `manage_prowler_realtime`. Without it, write controls render disabled with `NO_PERMISSION_TOOLTIP`; never hide them.
- **URL state.** Tab, filters (`filter[...]`) and pagination live in search params parsed by `_lib/routes.ts`. Add a param there, not ad hoc in a component.
- **Fetch once per request.** Share a read between Server Components with the `cache()` helpers in `_lib/cached.ts` instead of calling the action twice.

## Tests

Pure helpers in `_lib/` and the actions/adapter carry most tests. Components are tested where they branch on demo data or permissions, and the tables have a browser test (`_components/realtime-tables.integration.test.tsx`).

```bash
cd ui
pnpm exec vitest run --project unit "app/(prowler)/realtime"
pnpm exec vitest run --project integration "app/(prowler)/realtime"
```
