"""Shared enums and static metadata for Audit Agent config and reporting."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class Provider(str, Enum):
    IAC = "iac"
    GITHUB = "github"
    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"
    KUBERNETES = "kubernetes"
    M365 = "m365"
    NHN = "nhn"

    @classmethod
    def clouds(cls) -> tuple[Provider, ...]:
        return (cls.AWS, cls.AZURE, cls.GCP, cls.KUBERNETES, cls.M365, cls.NHN)

    @classmethod
    def defaults(cls) -> list[str]:
        return [cls.IAC.value, cls.GITHUB.value]


class Framework(str, Enum):
    SOC2 = "soc2"
    ISO27001_2022 = "iso27001_2022"

    @classmethod
    def defaults(cls) -> list[str]:
        return [cls.SOC2.value, cls.ISO27001_2022.value]


class FrameworkFamily(str, Enum):
    SOC2 = "soc2"
    ISO27001 = "iso27001"


class Scanner(str, Enum):
    IAC = "iac"
    SECRETS = "secrets"
    DEPENDENCIES = "dependencies"
    LICENSES = "licenses"
    GITHUB_ACTIONS = "github_actions"


class TrivyScanner(str, Enum):
    MISCONFIG = "misconfig"
    SECRET = "secret"
    VULN = "vuln"
    LICENSE = "license"


class SecurityAspect(str, Enum):
    IAC = "iac"
    SECRETS = "secrets"
    DEPENDENCIES = "dependencies"
    LICENSES = "licenses"
    CONTAINERS = "containers"
    GITHUB = "github"
    GITHUB_ACTIONS = "github_actions"


@dataclass(frozen=True)
class AspectSpec:
    aspect: SecurityAspect
    label: str
    detail: str
    provider: Provider
    scanner: Scanner | None = None


ASPECT_SPECS: tuple[AspectSpec, ...] = (
    AspectSpec(
        SecurityAspect.IAC,
        "IaC / config",
        "Terraform, Docker, K8s, CloudFormation misconfigurations",
        Provider.IAC,
        Scanner.IAC,
    ),
    AspectSpec(
        SecurityAspect.SECRETS,
        "Secrets in source",
        "Hardcoded credentials and tokens (Trivy secret)",
        Provider.IAC,
        Scanner.SECRETS,
    ),
    AspectSpec(
        SecurityAspect.DEPENDENCIES,
        "Dependencies / CVEs",
        "Lockfile and package vulnerabilities (Trivy vuln)",
        Provider.IAC,
        Scanner.DEPENDENCIES,
    ),
    AspectSpec(
        SecurityAspect.LICENSES,
        "License compliance",
        "Third-party license risk (Trivy license)",
        Provider.IAC,
        Scanner.LICENSES,
    ),
    AspectSpec(
        SecurityAspect.CONTAINERS,
        "Containers / Dockerfiles",
        "Dockerfile and container config issues via IaC",
        Provider.IAC,
    ),
    AspectSpec(
        SecurityAspect.GITHUB,
        "GitHub hardening",
        "Branch protection, secret scanning, Dependabot, org settings",
        Provider.GITHUB,
    ),
    AspectSpec(
        SecurityAspect.GITHUB_ACTIONS,
        "GitHub Actions / CI-CD",
        "Workflow security and supply-chain risks in Actions",
        Provider.GITHUB,
        Scanner.GITHUB_ACTIONS,
    ),
)

SEVERITY_RANK: dict[str, int] = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "informational": 0,
    "info": 0,
    "unknown": 0,
}

SCANNER_TO_TRIVY: dict[Scanner, TrivyScanner] = {
    Scanner.IAC: TrivyScanner.MISCONFIG,
    Scanner.SECRETS: TrivyScanner.SECRET,
    Scanner.DEPENDENCIES: TrivyScanner.VULN,
    Scanner.LICENSES: TrivyScanner.LICENSE,
}
