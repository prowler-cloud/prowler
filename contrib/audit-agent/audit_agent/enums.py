"""Shared enums for Audit Agent config and reporting."""

from __future__ import annotations

from enum import Enum


class Provider(str, Enum):
    """Prowler providers the Audit Agent can run."""

    IAC = "iac"
    GITHUB = "github"
    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"
    KUBERNETES = "kubernetes"
    M365 = "m365"
    NHN = "nhn"
    IMAGE = "image"
    LLM = "llm"

    @classmethod
    def clouds(cls) -> tuple[Provider, ...]:
        """Live cloud / cluster providers (need credentials)."""
        return (
            cls.AWS,
            cls.AZURE,
            cls.GCP,
            cls.KUBERNETES,
            cls.M365,
            cls.NHN,
        )

    @classmethod
    def defaults(cls) -> list[str]:
        return [cls.IAC.value, cls.GITHUB.value]


class Framework(str, Enum):
    """Short framework names accepted in config."""

    SOC2 = "soc2"
    ISO27001_2022 = "iso27001_2022"

    @classmethod
    def defaults(cls) -> list[str]:
        return [cls.SOC2.value, cls.ISO27001_2022.value]


class FrameworkFamily(str, Enum):
    """Control-family keys used in mapped findings."""

    SOC2 = "soc2"
    ISO27001 = "iso27001"


class Scanner(str, Enum):
    """Boolean scanner toggles in config.scanners."""

    IAC = "iac"
    SECRETS = "secrets"
    DEPENDENCIES = "dependencies"
    LICENSES = "licenses"
    GITHUB_ACTIONS = "github_actions"


class TrivyScanner(str, Enum):
    """Values passed to `prowler iac --scanners`."""

    MISCONFIG = "misconfig"
    SECRET = "secret"
    VULN = "vuln"
    LICENSE = "license"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"
    INFO = "info"
    UNKNOWN = "unknown"


class SecurityAspect(str, Enum):
    """Report aspect ids (security coverage table)."""

    IAC = "iac"
    SECRETS = "secrets"
    DEPENDENCIES = "dependencies"
    LICENSES = "licenses"
    CONTAINERS = "containers"
    GITHUB = "github"
    GITHUB_ACTIONS = "github_actions"
    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"
    KUBERNETES = "kubernetes"
    M365 = "m365"
    NHN = "nhn"


SEVERITY_RANK: dict[str, int] = {
    Severity.CRITICAL.value: 4,
    Severity.HIGH.value: 3,
    Severity.MEDIUM.value: 2,
    Severity.LOW.value: 1,
    Severity.INFORMATIONAL.value: 0,
    Severity.INFO.value: 0,
    Severity.UNKNOWN.value: 0,
}

# Config scanner key → Trivy CLI scanner value
SCANNER_TO_TRIVY: dict[Scanner, TrivyScanner] = {
    Scanner.IAC: TrivyScanner.MISCONFIG,
    Scanner.SECRETS: TrivyScanner.SECRET,
    Scanner.DEPENDENCIES: TrivyScanner.VULN,
    Scanner.LICENSES: TrivyScanner.LICENSE,
}
