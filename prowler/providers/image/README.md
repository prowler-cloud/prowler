# Container Image Provider (PoC)

This is a proof of concept implementation of a container image scanning provider for Prowler using Trivy.

## Overview

The Image Provider follows the Tool/Wrapper pattern established by the IaC provider. It delegates all scanning logic to Trivy's `trivy image` command and converts the output to Prowler's finding format.

## Prerequisites

### Trivy Installation

Trivy must be installed and available in your PATH. Install using one of these methods:

**macOS (Homebrew):**
```bash
brew install trivy
```

**Linux (apt):**
```bash
sudo apt-get install trivy
```

**Linux (rpm):**
```bash
sudo yum install trivy
```

**Docker:**
```bash
docker pull aquasecurity/trivy
```

For more installation options, see the [Trivy documentation](https://trivy.dev/latest/getting-started/installation/).

## Usage

### Basic Scan

Scan a single container image:
```bash
poetry run python prowler-cli.py image --image nginx:latest
```

### Multiple Images

Scan multiple images in a single run:
```bash
poetry run python prowler-cli.py image --image nginx:latest --image alpine:3.18 --image python:3.11
```

### From File

Scan images listed in a file (one per line):
```bash
# images.txt
nginx:latest
alpine:3.18
python:3.11
# This line is a comment and will be ignored

poetry run python prowler-cli.py image --image-list images.txt
```

### Scanner Selection

By default, the provider uses vulnerability and secret scanners. Customize with:
```bash
# Vulnerability scanning only
poetry run python prowler-cli.py image --image nginx:latest --scanners vuln

# All scanners
poetry run python prowler-cli.py image --image nginx:latest --scanners vuln secret misconfig license
```

### Severity Filtering

Filter findings by severity:
```bash
# Critical and high only
poetry run python prowler-cli.py image --image nginx:latest --trivy-severity CRITICAL HIGH
```

### Ignore Unfixed Vulnerabilities

Skip vulnerabilities without available fixes:
```bash
poetry run python prowler-cli.py image --image nginx:latest --ignore-unfixed
```

### Custom Timeout

Adjust Trivy scan timeout (default: 5m):
```bash
poetry run python prowler-cli.py image --image large-image:latest --timeout 10m
```

### Output Formats

Export results in different formats:
```bash
# JSON and CSV (default includes html)
poetry run python prowler-cli.py image --image nginx:latest --output-formats json-ocsf csv

# Specify output directory
poetry run python prowler-cli.py image --image nginx:latest --output-directory ./scan-results
```

## CLI Reference

```
prowler image [OPTIONS]

Options:
  --image, -I              Container image to scan (can be specified multiple times)
  --image-list             File containing list of images to scan (one per line)
  --scanners               Trivy scanners: vuln, secret, misconfig, license
                           (default: vuln, secret)
  --trivy-severity         Filter: CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN
  --ignore-unfixed         Ignore vulnerabilities without fixes
  --timeout                Trivy scan timeout (default: 5m)

Standard Prowler Options:
  --output-formats, -M     Output formats (csv, json-ocsf, html)
  --output-directory, -o   Output directory
  --output-filename, -F    Custom output filename
  --verbose                Show all findings during execution
  --no-banner, -b          Hide Prowler banner
```

## Architecture

```
prowler/providers/image/
├── __init__.py
├── image_provider.py      # Main provider class
├── models.py              # ImageOutputOptions
├── README.md              # This file
└── lib/
    └── arguments/
        ├── __init__.py
        └── arguments.py   # CLI argument definitions
```

### Key Components

1. **ImageProvider** (`image_provider.py`):
   - Builds and executes `trivy image` commands
   - Parses JSON output from Trivy
   - Converts findings to `CheckReportImage` format
   - Supports scanning multiple images in sequence

2. **CheckReportImage** (`prowler/lib/check/models.py`):
   - Extends `Check_Report` base class
   - Stores vulnerability-specific fields (package name, versions)

3. **ImageOutputOptions** (`models.py`):
   - Customizes output filename generation

4. **CLI Arguments** (`lib/arguments/arguments.py`):
   - Defines image provider CLI arguments
   - Validates required arguments

## Known Limitations (PoC Scope)

1. **Public Registries Only**: No authentication for private registries
2. **No Local Tar Support**: Cannot scan local image tar files
3. **No SBOM Export**: Does not generate SBOM output
4. **No Compliance Mapping**: No compliance framework integration
5. **Sequential Scanning**: Images scanned one at a time (no parallelization)

## Future Work

For full implementation, consider:

1. **Registry Authentication**:
   - Docker config.json support
   - Environment variable credentials
   - Cloud provider registry integration (ECR, GCR, ACR)

2. **Local Image Support**:
   - Scan from tar files (`--input` flag)
   - Scan from Docker daemon

3. **SBOM Generation**:
   - CycloneDX output
   - SPDX output

4. **Performance**:
   - Parallel image scanning
   - Caching of vulnerability databases

5. **Compliance Integration**:
   - Map CVEs to compliance frameworks
   - Custom compliance definitions

6. **Enhanced Reporting**:
   - Image-specific HTML reports
   - Vulnerability trending

## Trivy Output Format

Trivy's JSON output structure for image scanning:

```json
{
  "Results": [
    {
      "Target": "nginx:latest (debian 11.7)",
      "Type": "debian",
      "Vulnerabilities": [
        {
          "VulnerabilityID": "CVE-2023-1234",
          "PkgName": "openssl",
          "InstalledVersion": "1.1.1n-0+deb11u4",
          "FixedVersion": "1.1.1n-0+deb11u5",
          "Severity": "HIGH",
          "Title": "Buffer overflow in...",
          "Description": "...",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2023-1234"
        }
      ],
      "Secrets": [...],
      "Misconfigurations": [...]
    }
  ]
}
```

## References

- [Trivy Documentation](https://trivy.dev/docs/latest/)
- [Trivy Image Scanning](https://trivy.dev/docs/latest/guide/target/container_image/)
- [Trivy JSON Output](https://trivy.dev/docs/latest/guide/configuration/reporting/)
- [Prowler IaC Provider](../iac/) - Reference implementation
