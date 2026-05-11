# Prowler Reverse Proxy Configuration

Ready-to-use nginx configuration for running Prowler behind a reverse proxy.

## Problem

Prowler's default Docker setup exposes two separate services:
- **UI** on port 3000
- **API** on port 8080

This causes CORS issues and authentication failures (especially SAML SSO) when accessed through an external reverse proxy, since the proxy typically exposes a single domain.

## Solution

This adds an nginx container that unifies both services behind a single port, correctly forwarding headers so that Django generates proper URLs for SAML ACS callbacks and API responses.

## Quick Start

From the prowler root directory:

    docker compose -f docker-compose.yml \
      -f contrib/reverse-proxy/docker-compose.reverse-proxy.yml \
      up -d

Access Prowler at http://localhost (port 80).

## With an External Reverse Proxy

Point your external reverse proxy to the prowler-nginx container on port 80.

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| PROWLER_PROXY_PORT | 80 | Port exposed by the nginx proxy |

### Example: Traefik

    services:
      nginx:
        labels:
          - "traefik.enable=true"
          - "traefik.http.routers.prowler.rule=Host(`prowler.example.com`)"
          - "traefik.http.routers.prowler.tls.certresolver=letsencrypt"
          - "traefik.http.services.prowler.loadbalancer.server.port=80"

### Example: Caddy

    prowler.example.com {
        reverse_proxy prowler-nginx:80
    }

## SAML SSO

If using SAML SSO behind a reverse proxy, also set the SAML_ACS_BASE_URL environment variable:

    SAML_ACS_BASE_URL=https://prowler.example.com

## Architecture

    Internet -> External Reverse Proxy -> prowler-nginx:80
                                            |-- /api/*          -> prowler-api:8080
                                            |-- /accounts/saml/ -> prowler-api:8080
                                            +-- /*              -> prowler-ui:3000
