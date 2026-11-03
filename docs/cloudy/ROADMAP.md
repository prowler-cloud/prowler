# Cloudy roadmap

Cloudy is Prowler App with every feature free. Upstream keeps 17 features
behind a "Prowler Cloud" upsell when self-hosted. Cloudy removes the upsell
everywhere; what remains is engineering: the features whose backend only
exists in Prowler's hosted product need an open-source backend.

The UI decides what to show from one registry, `ui/lib/cloudy/features.ts`.
A feature is either `available` (real UI, always on) or `building` (entry
points hidden, never sold). When a backend below ships, flip its row to
`available`, or turn it on per deployment without a rebuild:

```
NEXT_PUBLIC_CLOUDY_FEATURES=alerts,finding_triage
```

## Milestone 1 — done in this branch

- Every upsell modal, "Cloud" badge, "Explore Prowler Cloud" button,
  "Unlock" prompt and marketing banner removed from the UI.
- Unlocked now (backend already in the open-source API):
  API keys (`/api-keys`), report downloads, full findings list (no preview
  lock), single-finding Jira dispatch, bring-your-own-model Lighthouse AI.
- Rebrand to Cloudy: name, mark, favicon, metadata, product copy. `NOTICE`
  added; Apache-2.0 `LICENSE` unchanged.
- Visual system rebuilt on Taste Skill's "framed sheet" app style (light) and
  a cool near-black monitoring theme (dark): IBM Plex Sans/Mono, flat
  surfaces, one sky-teal hue for the primary action, selection and data, no
  gradients, glows, halos or spinning borders.
- `docker-compose.yml` builds the UI and API from this repo instead of
  pulling `prowlercloud/*` images.

## Milestone 2+ — open-source backends to write

Ordered by value to a self-hosted security team and by size. Each row lists
the endpoints the existing UI already calls, so the backend is written to an
existing contract and the UI needs no redesign.

| # | Feature (`features.ts` key) | Endpoints the UI expects | Size | Notes |
|---|---|---|---|---|
| 1 | Advanced scheduling (`advanced_scheduling`) | `POST/PATCH /schedules`, `/schedules/{id}`, `/schedules/bulk` with frequency, hour, day of week/month, interval hours | S | OSS only has `/schedules/daily`. Extend `ScheduleViewSet` onto django-celery-beat crontab/interval schedules. |
| 2 | Scan configuration (`scan_configuration`) | `/scan-configurations`, `/scan-configurations/{id}` | S | Per-provider check/service/region include-exclude lists fed into the scan task. |
| 3 | Finding triage (`finding_triage`) | `/finding-triages/{id}`, `/finding-triages/{id}/notes` | M | New `FindingTriage` + `FindingTriageNote` models (status, assignee, evidence for manual pass), RLS by tenant, RBAC permission. |
| 4 | Alerts (`alerts`) | `/alerts/rules`, `/alerts/recipients`, `/alerts/slack-channels`, `/alerts/dsl`, confirm/unsubscribe pages | M | Rules evaluated after each scan in Celery; deliver via email (SMTP) and the existing Slack integration. |
| 5 | Cross-provider compliance (`cross_provider_compliance`) | `/cross-provider-compliance-overviews`, `/cross-provider-frameworks`, `.../pdf` | M | Aggregate latest scan per provider into one framework view; reuse the existing PDF report generator. |
| 6 | AWS/Azure/GCP organizations (`*_organizations`) | `/organizations`, `/organization-nodes`, `/organization-secrets` | L | Discover accounts/subscriptions/projects from the management account and create providers in bulk; StackSet/role helper for AWS. |
| 7 | CLI import (`cli_import`) | `POST /ingestions`, `GET /ingestions/{id}` | M | Accept Prowler CLI OCSF JSON, validate, load as a scan. Useful for air-gapped accounts. |
| 8 | SAML extra domains (`saml_domains`) | `additional_email_domains` on `/saml-config` | S | Many-to-one domain table on `SAMLConfiguration`. |
| 9 | Grouped Jira dispatch (`jira_dispatch`, grouped) | finding-group payload on the Jira dispatch action | S | One issue per finding group instead of per finding. |
| — | Registry (`registry`) | Hosted Prowler catalogue | — | Out of scope: it is Prowler's hosted service, not software. Stays hidden. |

Also for later:

- Point the API's `prowler @ git+...` dependency at this fork once Cloudy
  carries scanner changes (today it tracks upstream master).
- Publish `cloudy/api` and `cloudy/ui` images from CI.
- Keep upstream merges cheap: brand components keep their upstream export
  names, and gating changes are confined to `features.ts` and the call sites
  it lists.

## Staying in sync with upstream

```
git fetch upstream
git merge upstream/master   # conflicts concentrate in the files listed above
```
