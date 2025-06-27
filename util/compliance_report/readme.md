# ThreatScore Compliance Report Generator

This tool generates a PDF compliance report using Prowler's API endpoints, summarizing compliance requirements, risk levels, and findings for a given scan and compliance framework.

## Features
- Authenticates with the Prowler API using email and password
- Retrieves compliance requirements and attributes for a given scan and compliance framework
- Generates a visually rich PDF report, including:
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
python3 util/compliance_report/generate_threatscore_report.py \
    --scan-id <scan_id> \
    --compliance-id <compliance_id> \
    --email <email> \
    --password <password> \
    [--output <output_path>] \
    [--base-url <base_url>] \
    [--only-failed] \
    [--min-risk-level <level>]
```

### Arguments
- `--scan-id` (required): ID of the scan executed by Prowler.
- `--compliance-id` (required): Compliance framework ID (e.g., `prowler_threatscore_azure`, `nis2_azure`).
- `--email` (required): Email for API authentication.
- `--password` (required): Password for API authentication.
- `--output` (optional): Output PDF file path (default: `threatscore_report.pdf`).
- `--base-url` (optional): Base URL for the API (default: `http://localhost:8080`).
- `--only-failed` (optional): Only include failed requirements in the report.
- `--min-risk-level` (optional): Minimum risk level for critical failed requirements (default: 4).

### Example
```bash
python3 util/compliance_report/generate_threatscore_report.py \
    --scan-id 12345678-1234-5678-1234-567812345678 \
    --compliance-id prowler_threatscore_azure \
    --email user@example.com \
    --password mypassword \
    --output my_report.pdf \
    --base-url http://localhost:8080 \
    --only-failed \
    --min-risk-level 4
```

## Output
- The script will generate a PDF file with:
  - Compliance framework summary
  - Compliance score by section (with bar chart)
  - Table of critical failed requirements (if any)
  - Detailed breakdown of each requirement and its findings

## Notes
- The script authenticates with the API and retrieves all necessary data automatically.
- If you encounter authentication errors, check your email, password, and API URL.
- For more details, see the script source: `util/compliance_report/generate_threatscore_report.py`
