# Cloudflare Provider - Quick Reference Card

## Installation
Already included in Prowler - no additional installation needed!

## Authentication

### Method 1: API Token (Recommended)
```bash
export CLOUDFLARE_API_TOKEN="your-token"
prowler cloudflare
```

### Method 2: API Key + Email
```bash
export CLOUDFLARE_API_KEY="your-key"
export CLOUDFLARE_API_EMAIL="your@email.com"
prowler cloudflare
```

### Create API Token
1. Visit: https://dash.cloudflare.com/profile/api-tokens
2. Click "Create Token"
3. Required permissions:
   - Zone:Read
   - Zone Settings:Read
   - Firewall Services:Read
   - User:Read

## Common Commands

```bash
# Basic scan
prowler cloudflare

# Test connection
prowler cloudflare --test-connection

# Scan specific zones
prowler cloudflare --zone-id zone_abc123 zone_def456

# Run specific checks
prowler cloudflare -c ssl_tls_minimum_version firewall_waf_enabled

# List all checks
prowler cloudflare --list-checks

# Multiple output formats
prowler cloudflare -o json html csv

# JSON output only
prowler cloudflare -o json -F json

# With mutelist
prowler cloudflare --mutelist-file mutelist.yaml

# Specific service
prowler cloudflare --service ssl firewall
```

## Available Checks

| Check ID | Service | Severity | Description |
|----------|---------|----------|-------------|
| `firewall_waf_enabled` | firewall | High | Ensures WAF is enabled |
| `ssl_tls_minimum_version` | ssl | High | Ensures TLS 1.2+ is enforced |
| `ssl_always_use_https` | ssl | Medium | Ensures HTTP→HTTPS redirect |

## Services

- **firewall**: Firewall rules and WAF
- **ssl**: SSL/TLS configuration and certificates

## Output Files

Default output location: `./output/`
Format: `prowler-output-{account_name}-{timestamp}.{format}`

## Scoping

```bash
# Specific zones only
prowler cloudflare --zone-id zone1 zone2

# Specific accounts only
prowler cloudflare --account-id account1 account2
```

## Troubleshooting

### Authentication fails
```bash
# Check environment variables
echo $CLOUDFLARE_API_TOKEN

# Test with explicit token
prowler cloudflare --api-token "your-token" --test-connection
```

### Permission denied
- Verify API token has required permissions
- Check token is not expired

### Rate limiting
- Use zone scoping: `--zone-id zone1`
- Run specific checks: `-c check_name`

## Quick Start (3 Steps)

1. **Get API Token**
   ```bash
   # Visit: https://dash.cloudflare.com/profile/api-tokens
   ```

2. **Set Environment Variable**
   ```bash
   export CLOUDFLARE_API_TOKEN="your-token"
   ```

3. **Run Scan**
   ```bash
   prowler cloudflare
   ```

## Architecture

```
cloudflare/
├── cloudflare_provider.py    # Main provider
├── models.py                  # Data models
├── lib/
│   ├── arguments/            # CLI args
│   ├── service/              # Base service
│   └── mutelist/             # Mutelist
└── services/
    ├── firewall/             # Firewall service
    │   └── firewall_waf_enabled/
    └── ssl/                  # SSL/TLS service
        ├── ssl_tls_minimum_version/
        └── ssl_always_use_https/
```

## Adding New Checks

1. Identify service (or create new one)
2. Create check directory: `services/{service}/{check_name}/`
3. Create check file: `{check_name}.py`
4. Create metadata: `{check_name}.metadata.json`
5. Run: `prowler cloudflare -c {check_name}`

## Environment Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `CLOUDFLARE_API_TOKEN` | API Token | `abc123...` |
| `CLOUDFLARE_API_KEY` | Global API Key | `def456...` |
| `CLOUDFLARE_API_EMAIL` | Account email | `user@example.com` |

## Common Issues

**Issue**: No zones found
**Solution**: Check API token has Zone:Read permission

**Issue**: Some checks fail
**Solution**: Verify zone plan supports feature (e.g., WAF needs Pro+)

**Issue**: Slow scan
**Solution**: Use zone scoping or specific checks

## Resources

- Cloudflare API Docs: https://developers.cloudflare.com/api/
- Provider README: `prowler/providers/cloudflare/README.md`
- Setup Guide: `CLOUDFLARE_PROVIDER_SETUP.md`

## File Locations

- **Provider**: `prowler/providers/cloudflare/cloudflare_provider.py`
- **CLI Args**: `prowler/providers/cloudflare/lib/arguments/arguments.py`
- **Services**: `prowler/providers/cloudflare/services/`
- **Checks**: `prowler/providers/cloudflare/services/{service}/{check}/`

## Support

For issues or questions:
- GitHub: https://github.com/prowler-cloud/prowler
- Documentation: Main Prowler docs
- API Docs: Cloudflare Developer Portal

---
**Version**: 1.0 | **Date**: 2025-10-22 | **Status**: Production Ready ✅
