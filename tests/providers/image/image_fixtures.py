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
    "References": [
        "https://avd.aquasec.com/nvd/cve-2024-1234",
        "https://nvd.nist.gov/vuln/detail/CVE-2024-1234",
        "https://www.cve.org/CVERecord?id=CVE-2024-1234",
        "https://security.alpinelinux.org/vuln/CVE-2024-1234",
    ],
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

SAMPLE_VULNERABILITY_WITHOUT_CVE_ORG_REFERENCE = {
    "VulnerabilityID": "CVE-2024-5678",
    "PkgID": "libcrypto3@3.3.2-r0",
    "PkgName": "libcrypto3",
    "InstalledVersion": "3.3.2-r0",
    "FixedVersion": "3.3.2-r1",
    "Severity": "HIGH",
    "Title": "OpenSSL advisory without cve.org reference",
    "Description": "A vulnerability with references but no cve.org reference.",
    "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-5678",
    "References": [
        "https://avd.aquasec.com/nvd/cve-2024-5678",
        "https://nvd.nist.gov/vuln/detail/CVE-2024-5678",
        "https://security.alpinelinux.org/vuln/CVE-2024-5678",
    ],
}

SAMPLE_CVE_WITHOUT_REFERENCES_FINDING = {
    "VulnerabilityID": "CVE-2024-9012",
    "PkgID": "busybox@1.36.1-r8",
    "PkgName": "busybox",
    "InstalledVersion": "1.36.1-r8",
    "FixedVersion": "1.36.1-r9",
    "Severity": "MEDIUM",
    "Title": "Busybox fallback CVE",
    "Description": "A vulnerability without explicit references.",
    "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-9012",
}

SAMPLE_NON_CVE_VULNERABILITY_FINDING = {
    "VulnerabilityID": "GHSA-abcd-1234-efgh",
    "PkgID": "custompkg@0.0.1",
    "PkgName": "custompkg",
    "InstalledVersion": "0.0.1",
    "Severity": "HIGH",
    "Title": "Non-CVE advisory",
    "Description": "An advisory without a CVE identifier.",
    "PrimaryURL": "https://avd.aquasec.com/nvd/ghsa-abcd-1234-efgh",
    "References": [
        "https://avd.aquasec.com/nvd/ghsa-abcd-1234-efgh",
        "https://github.com/advisories/GHSA-abcd-1234-efgh",
    ],
}

# Sample image SHA for testing (first 12 chars of a sha256 digest)
SAMPLE_IMAGE_SHA = "c1aabb73d233"
SAMPLE_IMAGE_ID = f"sha256:{SAMPLE_IMAGE_SHA}abcdef1234567890"

# Full Trivy JSON output structure with a single vulnerability
SAMPLE_TRIVY_IMAGE_OUTPUT = {
    "Metadata": {
        "ImageID": SAMPLE_IMAGE_ID,
        "RepoDigests": [f"alpine@sha256:{SAMPLE_IMAGE_SHA}abcdef1234567890"],
    },
    "Results": [
        {
            "Target": "alpine:3.18 (alpine 3.18.0)",
            "Type": "alpine",
            "Vulnerabilities": [SAMPLE_VULNERABILITY_FINDING],
            "Secrets": [],
            "Misconfigurations": [],
        }
    ],
}

# Full Trivy JSON output with mixed finding types
SAMPLE_TRIVY_MULTI_TYPE_OUTPUT = {
    "Metadata": {
        "ImageID": SAMPLE_IMAGE_ID,
        "RepoDigests": [f"myimage@sha256:{SAMPLE_IMAGE_SHA}abcdef1234567890"],
    },
    "Results": [
        {
            "Target": "myimage:latest (debian 12)",
            "Type": "debian",
            "Vulnerabilities": [SAMPLE_VULNERABILITY_FINDING],
            "Secrets": [SAMPLE_SECRET_FINDING],
            "Misconfigurations": [SAMPLE_MISCONFIGURATION_FINDING],
        }
    ],
}

# Trivy output with only RepoDigests (no ImageID) for fallback testing
SAMPLE_TRIVY_REPO_DIGEST_ONLY_OUTPUT = {
    "Metadata": {
        "RepoDigests": ["alpine@sha256:e5f6g7h8i9j0abcdef1234567890"],
    },
    "Results": [
        {
            "Target": "alpine:3.18 (alpine 3.18.0)",
            "Type": "alpine",
            "Vulnerabilities": [SAMPLE_VULNERABILITY_FINDING],
            "Secrets": [],
            "Misconfigurations": [],
        }
    ],
}

# Trivy output with no Metadata at all
SAMPLE_TRIVY_NO_METADATA_OUTPUT = {
    "Results": [
        {
            "Target": "alpine:3.18 (alpine 3.18.0)",
            "Type": "alpine",
            "Vulnerabilities": [SAMPLE_VULNERABILITY_FINDING],
            "Secrets": [],
            "Misconfigurations": [],
        }
    ],
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


def get_repo_digest_only_trivy_output():
    """Return Trivy output with only RepoDigests (no ImageID) as string."""
    return json.dumps(SAMPLE_TRIVY_REPO_DIGEST_ONLY_OUTPUT)


def get_no_metadata_trivy_output():
    """Return Trivy output with no Metadata as string."""
    return json.dumps(SAMPLE_TRIVY_NO_METADATA_OUTPUT)
