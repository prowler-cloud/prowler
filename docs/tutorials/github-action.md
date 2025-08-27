# GitHub Actions Security Scanning with Prowler

Prowler integrates with [zizmor](https://github.com/woodruffw/zizmor) to provide comprehensive security scanning for GitHub Actions workflows. This feature helps identify security vulnerabilities and misconfigurations in your CI/CD pipelines.

## Prerequisites

Before using the GitHub Actions provider, you need to install zizmor:

### Install Zizmor

```bash
# Using Cargo (Rust package manager)
cargo install zizmor

# Or download from GitHub releases
# See: https://github.com/woodruffw/zizmor/releases
```

## What Does It Scan?

The GitHub Actions provider scans for:

- **Template injection vulnerabilities** - Prevents attacker-controlled code execution
- **Accidental credential persistence and leakage** - Detects exposed secrets
- **Excessive permission scopes** - Identifies over-privileged workflows
- **Impostor commits and confusable git references** - Spots suspicious references
- **Other GitHub Actions security best practices**

## Basic Usage

### Scan Local Workflows

To scan GitHub Actions workflows in your current directory:

```bash
prowler github_action
```

To scan workflows in a specific directory:

```bash
prowler github_action --workflow-path /path/to/repository
```

### Scan Remote Repository

To scan a GitHub repository directly:

```bash
# Public repository
prowler github_action --repository-url https://github.com/user/repo

# Private repository with authentication
prowler github_action --repository-url https://github.com/user/private-repo \
  --github-username YOUR_USERNAME \
  --personal-access-token YOUR_TOKEN
```

## Authentication Options

For scanning private repositories, Prowler supports multiple authentication methods:

### Personal Access Token

```bash
prowler github_action --repository-url https://github.com/org/private-repo \
  --github-username YOUR_USERNAME \
  --personal-access-token YOUR_PAT
```

### OAuth App Token

```bash
prowler github_action --repository-url https://github.com/org/private-repo \
  --oauth-app-token YOUR_OAUTH_TOKEN
```

### Environment Variables

You can also set authentication via environment variables:

```bash
export GITHUB_USERNAME=your-username
export GITHUB_PERSONAL_ACCESS_TOKEN=your-token
# or
export GITHUB_OAUTH_APP_TOKEN=your-oauth-token

prowler github_action --repository-url https://github.com/org/private-repo
```

## Excluding Workflows

To exclude specific workflows or patterns from scanning:

```bash
prowler github_action --exclude-workflows "test-*.yml" "experimental/*"
```

## Output Formats

The GitHub Actions provider supports all standard Prowler output formats:

```bash
# Generate HTML, CSV, and JSON reports
prowler github_action --output-formats html csv json-ocsf

# Custom output directory
prowler github_action --output-directory ./security-reports

# Custom output filename
prowler github_action --output-filename github-actions-security-scan
```

## Examples

### Complete Security Scan with Full Reporting

```bash
prowler github_action \
  --repository-url https://github.com/my-org/my-repo \
  --personal-access-token $GITHUB_TOKEN \
  --output-formats html csv json-ocsf \
  --output-directory ./security-reports \
  --verbose
```

### Scan Multiple Local Repositories

```bash
for repo in repo1 repo2 repo3; do
  echo "Scanning $repo..."
  prowler github_action \
    --workflow-path ./$repo \
    --output-filename "scan-$repo" \
    --output-directory ./reports
done
```

## Understanding Results

The scanner will identify issues with different severity levels:

- **CRITICAL/HIGH**: Immediate security risks that should be addressed urgently
- **MEDIUM**: Potential security issues that should be reviewed
- **LOW/INFO**: Best practice violations or informational findings

Each finding includes:
- Description of the security issue
- Affected workflow file and line number
- Remediation recommendations
- Links to relevant documentation

## Integration with CI/CD

You can integrate Prowler's GitHub Actions scanning into your CI/CD pipeline:

```yaml
name: Security Scan
on:
  push:
    paths:
      - '.github/workflows/**'
  pull_request:
    paths:
      - '.github/workflows/**'

jobs:
  scan-workflows:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Install zizmor
        run: |
          cargo install zizmor
      
      - name: Install Prowler
        run: |
          pip install prowler
      
      - name: Scan GitHub Actions workflows
        run: |
          prowler github_action \
            --workflow-path . \
            --output-formats json-ocsf \
            --output-directory ./reports
      
      - name: Upload scan results
        uses: actions/upload-artifact@v4
        with:
          name: workflow-security-scan
          path: ./reports/
```

## Troubleshooting

### Zizmor Not Found

If you get an error about zizmor not being found:

1. Ensure zizmor is installed: `which zizmor`
2. Install it using: `cargo install zizmor`
3. Make sure it's in your PATH

### Authentication Issues

For private repositories:
- Ensure your token has appropriate permissions (`repo` scope for private repos)
- Check that credentials are correctly set
- Verify the repository URL is correct

### No Findings

If no findings are returned:
- Verify that `.github/workflows/` directory exists
- Check that workflow files have `.yml` or `.yaml` extension
- Run with `--verbose` flag for more details