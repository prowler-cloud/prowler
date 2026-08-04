<p align="center">
  <img src="https://raw.githubusercontent.com/prowler-cloud/prowler/master/docs/dockerhub/prowler-logo.svg" width="252" alt="Prowler">
</p>
<p align="center">
  <b>Prowler</b> is the Open Cloud Security platform trusted by thousands to automate security and compliance in any cloud environment — AWS, Azure, Google Cloud, Kubernetes, M365, GitHub and more.
</p>
<p align="center">
  <b>Learn more at <a href="https://prowler.com">prowler.com</a> · <a href="https://goto.prowler.com/slack">Join our Slack community</a></b>
</p>

<p align="center">
  <a href="https://github.com/prowler-cloud/prowler"><img alt="GitHub" src="https://img.shields.io/github/stars/prowler-cloud/prowler?style=social"></a>
  <a href="https://github.com/prowler-cloud/prowler/releases"><img alt="Version" src="https://img.shields.io/github/v/release/prowler-cloud/prowler"></a>
  <a href="https://pypi.org/project/prowler/"><img alt="PyPI" src="https://img.shields.io/pypi/v/prowler.svg"></a>
  <a href="https://github.com/prowler-cloud/prowler"><img alt="License" src="https://img.shields.io/github/license/prowler-cloud/prowler"></a>
</p>

---

# Prowler container images

All Prowler images are built from a single repository — [github.com/prowler-cloud/prowler](https://github.com/prowler-cloud/prowler) — and published together on every release.

| Image | What it is | Dockerfile |
|---|---|---|
| [`prowlercloud/prowler`](https://hub.docker.com/r/prowlercloud/prowler) | **Prowler CLI.** Runs scans from your terminal, a CI job, a Kubernetes Job or any container platform. | [`Dockerfile`](https://github.com/prowler-cloud/prowler/blob/master/Dockerfile) |
| [`prowlercloud/prowler-api`](https://hub.docker.com/r/prowlercloud/prowler-api) | **Prowler Local Server — API.** Django REST backend plus the Celery worker and scheduler that run scans and store results. | [`api/Dockerfile`](https://github.com/prowler-cloud/prowler/blob/master/api/Dockerfile) |
| [`prowlercloud/prowler-ui`](https://hub.docker.com/r/prowlercloud/prowler-ui) | **Prowler Local Server — UI.** Next.js web interface for launching scans and exploring findings. | [`ui/Dockerfile`](https://github.com/prowler-cloud/prowler/blob/master/ui/Dockerfile) |
| [`prowlercloud/prowler-mcp`](https://hub.docker.com/r/prowlercloud/prowler-mcp) | **Prowler MCP.** Gives AI assistants access to the Prowler ecosystem over the Model Context Protocol. | [`mcp_server/Dockerfile`](https://github.com/prowler-cloud/prowler/blob/master/mcp_server/Dockerfile) |
| [`toniblyx/prowler`](https://hub.docker.com/r/toniblyx/prowler) | **Legacy home of the Prowler CLI image.** Still mirrored on every release for backwards compatibility. New deployments should use `prowlercloud/prowler`. | [`Dockerfile`](https://github.com/prowler-cloud/prowler/blob/master/Dockerfile) |

All images are published for `linux/amd64` and `linux/arm64`.

## Tags

| Tag | Meaning |
|---|---|
| `stable` | Always points to the latest stable release. **Recommended for production.** |
| `<x.y.z>` | A specific release, e.g. `5.14.0`. Immutable. |
| `latest` | Built from the `master` branch on every merge. Not a stable version. |
| `<short-sha>` | A specific `master` commit (`prowler-api`, `prowler-ui` and `prowler-mcp` only). |

`v3-*` and `v4-*` tags on `prowlercloud/prowler` are frozen historical artifacts of Prowler v3/v4 and no longer receive updates.

## Other registries

The Prowler CLI image is also available on AWS Public ECR: [`public.ecr.aws/prowler-cloud/prowler`](https://gallery.ecr.aws/prowler-cloud/prowler).

---

# Quick start

## Prowler Local Server (UI + API)

```console
curl -LO https://raw.githubusercontent.com/prowler-cloud/prowler/refs/heads/master/docker-compose.yml
curl -LO https://raw.githubusercontent.com/prowler-cloud/prowler/refs/heads/master/.env
docker compose up -d
```

Then open http://localhost:3000 and sign up with your email and password.

Full guide: [Prowler Local Server installation](https://docs.prowler.com/getting-started/installation/prowler-app)

## Prowler CLI

```console
docker run -ti --rm \
  -v /your/local/dir/prowler-output:/home/prowler/output \
  --name prowler \
  --env AWS_ACCESS_KEY_ID \
  --env AWS_SECRET_ACCESS_KEY \
  --env AWS_SESSION_TOKEN \
  prowlercloud/prowler:stable aws
```

Swap `aws` for `azure`, `gcp`, `kubernetes`, `m365` or `github` to scan another provider. The CLI is also on PyPI: `pip install prowler`.

Full guide: [Prowler CLI installation](https://docs.prowler.com/getting-started/installation/prowler-cli)

## Prowler MCP

```console
# STDIO mode (for local MCP clients)
docker run --rm -i prowlercloud/prowler-mcp

# HTTP mode (for remote access)
docker run --rm -p 8000:8000 prowlercloud/prowler-mcp \
  --transport http --host 0.0.0.0 --port 8000
```

Full guide: [Prowler MCP installation](https://docs.prowler.com/getting-started/installation/prowler-mcp)

> **Note on architecture:** if your workstation's architecture is incompatible, set `DOCKER_DEFAULT_PLATFORM=linux/amd64` or pass `--platform linux/amd64` to your Docker command.

---

# What Prowler covers

Hundreds of built-in checks mapped to the frameworks you get audited against — CIS, NIST 800 / CSF, CISA, PCI-DSS, GDPR, HIPAA, FFIEC, SOC2, GXP, FedRAMP, RBI, AWS Well-Architected (Security Pillar), AWS FTR, ENS — plus your own custom frameworks.

For live check, service, framework and category counts, see [**Prowler Hub**](https://hub.prowler.com).

List what's available for any provider:

```console
prowler <provider> --list-checks
prowler <provider> --list-services
prowler <provider> --list-compliance
prowler <provider> --list-categories
```

# Documentation and support

- **Documentation:** [docs.prowler.com](https://docs.prowler.com/)
- **Source:** [github.com/prowler-cloud/prowler](https://github.com/prowler-cloud/prowler)
- **Issues:** [github.com/prowler-cloud/prowler/issues](https://github.com/prowler-cloud/prowler/issues)
- **Community:** [Prowler Slack](https://goto.prowler.com/slack)
- **Troubleshooting:** [docs.prowler.com/troubleshooting](https://docs.prowler.com/troubleshooting)

# License

Prowler is licensed under the Apache License 2.0. A copy is available at http://www.apache.org/licenses/LICENSE-2.0.
