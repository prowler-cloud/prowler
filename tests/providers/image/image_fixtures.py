import json

# Sample vulnerability finding from Trivy
SAMPLE_VULNERABILITY_FINDING = {
    "VulnerabilityID": "CVE-2024-1234",
    "PkgID": "openssl@1.1.1k-r0",
    "PkgName": "openssl",
    "InstalledVersion": "1.1.1k-r0",
    "FixedVersion": "1.1.1l-r0",
    "Severity": "HIGH",
    "Title": "OpenSSL Buffer Overflow",
    "Description": "A buffer overflow vulnerability in OpenSSL allows remote attackers to execute arbitrary code.",
    "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-1234",
}

# Sample secret finding from Trivy
SAMPLE_SECRET_FINDING = {
    "RuleID": "aws-access-key-id",
    "Category": "AWS",
    "Severity": "CRITICAL",
    "Title": "AWS Access Key ID",
    "StartLine": 10,
    "EndLine": 10,
    "Match": "AKIA...",
}

# Sample misconfiguration finding from Trivy
SAMPLE_MISCONFIGURATION_FINDING = {
    "ID": "DS001",
    "Title": "Dockerfile should not use latest tag",
    "Description": "Using latest tag can cause unpredictable builds.",
    "Severity": "MEDIUM",
    "Resolution": "Use a specific version tag instead of latest",
    "PrimaryURL": "https://avd.aquasec.com/misconfig/ds001",
}

# Sample finding with UNKNOWN severity
SAMPLE_UNKNOWN_SEVERITY_FINDING = {
    "VulnerabilityID": "CVE-2024-9999",
    "PkgID": "test-pkg@0.0.1",
    "PkgName": "test-pkg",
    "InstalledVersion": "0.0.1",
    "Severity": "UNKNOWN",
    "Title": "Unknown severity issue",
    "Description": "An issue with unknown severity.",
}

# Full Trivy JSON output structure with a single vulnerability
SAMPLE_TRIVY_IMAGE_OUTPUT = {
    "Results": [
        {
            "Target": "alpine:3.18 (alpine 3.18.0)",
            "Type": "alpine",
            "Vulnerabilities": [SAMPLE_VULNERABILITY_FINDING],
            "Secrets": [],
            "Misconfigurations": [],
        }
    ]
}

# Full Trivy JSON output with mixed finding types
SAMPLE_TRIVY_MULTI_TYPE_OUTPUT = {
    "Results": [
        {
            "Target": "myimage:latest (debian 12)",
            "Type": "debian",
            "Vulnerabilities": [SAMPLE_VULNERABILITY_FINDING],
            "Secrets": [SAMPLE_SECRET_FINDING],
            "Misconfigurations": [SAMPLE_MISCONFIGURATION_FINDING],
        }
    ]
}


def get_sample_trivy_json_output():
    """Return sample Trivy JSON output as string."""
    return json.dumps(SAMPLE_TRIVY_IMAGE_OUTPUT)


def get_empty_trivy_output():
    """Return empty Trivy output as string."""
    return json.dumps({"Results": []})


def get_invalid_trivy_output():
    """Return invalid JSON output as string."""
    return "invalid json output"


def get_multi_type_trivy_output():
    """Return Trivy output with multiple finding types as string."""
    return json.dumps(SAMPLE_TRIVY_MULTI_TYPE_OUTPUT)
