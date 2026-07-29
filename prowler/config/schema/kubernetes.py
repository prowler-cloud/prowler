"""Kubernetes provider config schema with safety bounds."""

from typing import Optional

from pydantic import Field

from prowler.config.schema.base import ProviderConfigBase


class KubernetesProviderConfig(ProviderConfigBase):
    audit_log_maxbackup: Optional[int] = Field(
        default=None,
        ge=2,
        le=1000,
        description=(
            "API server audit log file rotations to keep. Range: 2..1000 "
            "(CIS Kubernetes 1.2.18 recommends ≥10)."
        ),
    )
    audit_log_maxsize: Optional[int] = Field(
        default=None,
        ge=10,
        le=10000,
        description=(
            "Max MB per audit log file before rotation. Range: 10..10000 MB "
            "(CIS Kubernetes 1.2.19 recommends ≥100 MB)."
        ),
    )
    audit_log_maxage: Optional[int] = Field(
        default=None,
        ge=7,
        le=3650,
        description=(
            "Days an audit log file is retained. Range: 7..3650 "
            "(CIS Kubernetes 1.2.17 recommends ≥30 days)."
        ),
    )
    apiserver_strong_ciphers: Optional[list[str]] = Field(
        default=None,
        description="Whitelist of strong TLS cipher suites required on the API server.",
    )
    kubelet_strong_ciphers: Optional[list[str]] = Field(
        default=None,
        description="Whitelist of strong TLS cipher suites required on kubelet.",
    )
