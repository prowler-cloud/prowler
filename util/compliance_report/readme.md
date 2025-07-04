# ThreatScore Compliance Report Generator

This tool generates a compliance PDF report using Prowler's API endpoints, summarizing requirements, risk levels, and findings for a given scan and compliance framework.

## Features
- Authenticate with the Prowler API using email+password or token
- Retrieve compliance requirements and attributes for a given scan and framework
- Generate a visually rich PDF report, including:
  - Compliance summary and description
  - Compliance score by section (with charts)
  - Critical failed requirements (with risk and weight)
  - Detailed requirements and findings

## Requirements
- Python 3.7+
- Dependencies: `matplotlib`, `requests`, `reportlab`

Install dependencies with:
```bash
pip install matplotlib requests reportlab
```

## Usage

```bash
python3 util/compliance_report/threatscore_report_generator.py \
    --scan-id <scan_id> \
    --compliance-id <compliance_id> \
    --email <email> \
    --password <password> \
    [--token <token>] \
    [--output <output_path>] \
    [--base-url <base_url>] \
    [--only-failed] \
    [--min-risk-level <level>]
```

> **Note:** You must provide either both `--email` and `--password`, or a `--token`. One of these authentication methods is required. If you provide a token, email and password are ignored.

### Arguments
- `--scan-id` (required): ID of the scan executed by Prowler.
- `--compliance-id` (required): Compliance framework ID (e.g., `prowler_threatscore_azure`, `nis2_azure`).
- `--email` (required*): Email for API authentication (*required if `--token` is not used).
- `--password` (required*): Password for API authentication (*required if `--token` is not used).
- `--token` (required*): JWT token for authentication (*required if `--email` and `--password` are not used).
- `--output` (optional): Output PDF file path (default: `threatscore_report.pdf`).
- `--base-url` (optional): Base URL for the API (default: `http://localhost:8080`).
- `--only-failed` (optional): Only include failed requirements in the report.
- `--min-risk-level` (optional): Minimum risk level to show critical failed requirements (default: 4).

### Example
```bash
python3 util/compliance_report/threatscore_report_generator.py \
    --scan-id 12345678-1234-5678-1234-567812345678 \
    --compliance-id prowler_threatscore_azure \
    --email user@example.com \
    --password mypassword \
    --output my_report.pdf \
    --base-url http://localhost:8080 \
    --only-failed \
    --min-risk-level 4
```

Or using a token:
```bash
python3 util/compliance_report/threatscore_report_generator.py \
    --scan-id 12345678-1234-5678-1234-567812345678 \
    --compliance-id prowler_threatscore_azure \
    --token eyJhbGciOi... \
    --output my_report.pdf
```

## Output
- The script will generate a PDF file with:
  - Compliance framework summary
  - Compliance score by section (with bar chart)
  - Table of critical failed requirements (if any)
  - Detailed breakdown of each requirement and its findings

## Notes
- The script can authenticate with email/password or directly with a JWT token. **One of these authentication methods is mandatory.**
- If you encounter authentication errors, check your credentials, token, and API URL.
- For more details, see the source code: `util/compliance_report/threatscore_report_generator.py`
