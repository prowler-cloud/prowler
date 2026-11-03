# Cloudy

Open-source, multi-cloud security posture and attack-path platform. Assets,
findings, compliance and attack paths across AWS, Azure, GCP, Kubernetes,
GitHub, M365 and more — with **every feature free**. No paid tier, no upsell,
no "available in Cloud" badges.

Cloudy is a fork of [Prowler](https://github.com/prowler-cloud/prowler)
(Apache-2.0). It keeps Prowler's scanner engine and its 1,000+ checks and
compliance frameworks, and changes the product around them:

- **No paywall.** Every upsell gate in the app is gone. Features whose backend
  upstream only runs in its hosted product are being rebuilt in the open —
  see [docs/cloudy/ROADMAP.md](docs/cloudy/ROADMAP.md).
- **A calmer, faster UI.** Rebuilt on Taste Skill's app-screen rules: flat
  surfaces, IBM Plex type, one accent spent on actions and data, light and
  dark themes at parity.
- **Self-hosted first.** `docker compose up` builds Cloudy's own UI and API.
  Telemetry (Sentry, PostHog) is off unless you set its env vars.

## Run it

```bash
git clone <your fork> cloudy && cd cloudy
docker compose up -d --build
# UI: http://localhost:3000   API: http://localhost:8080/api/v1/docs
```

Turn on a feature as soon as its backend lands, without rebuilding the UI:

```bash
NEXT_PUBLIC_CLOUDY_FEATURES=alerts,finding_triage
```

## Layout

| Path | What |
|---|---|
| `ui/` | Next.js app (Cloudy UI) |
| `api/` | Django REST API, Celery workers, attack-path graph (Neo4j) |
| `prowler/` | Scanner engine, providers, checks, compliance frameworks |
| `docs/cloudy/` | Cloudy roadmap and the original upstream README |

## License

Apache-2.0, see [LICENSE](LICENSE) and [NOTICE](NOTICE). "Prowler" is a
trademark of its owners; Cloudy is not affiliated with Prowler.
