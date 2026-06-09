"""Azure provider config schema with safety bounds.

Bounds aim for values that produce a meaningful security check; out-of-range
values are dropped (SDK runtime) or rejected (Prowler App backend).
"""

from typing import Annotated, Literal, Optional

from pydantic import AfterValidator, Field

from prowler.config.schema.base import ProviderConfigBase


def _validate_dotted_version(v: Optional[str]) -> Optional[str]:
    """Accept ``"8.2"``, ``"3.12"``, ``"17"`` style version strings.

    Used by App Service language version fields where the upstream APIs
    accept either ``MAJOR`` or ``MAJOR.MINOR`` notation.
    """
    if v is None:
        return v
    parts = v.split(".")
    if not (1 <= len(parts) <= 2) or not all(p.isdigit() for p in parts):
        raise ValueError(f"{v!r} is not a valid version (expected 'X' or 'X.Y')")
    return v


class AzureProviderConfig(ProviderConfigBase):
    # --- Network ---------------------------------------------------------
    shodan_api_key: Optional[str] = Field(
        default=None,
        max_length=512,
        description="API key for Shodan lookups on Azure public IPs.",
    )

    # --- Defender --------------------------------------------------------
    defender_attack_path_minimal_risk_level: Optional[
        Literal["Low", "Medium", "High", "Critical"]
    ] = Field(
        default=None,
        description="Minimum attack-path risk level worth a notification.",
    )

    # --- App Service ----------------------------------------------------
    php_latest_version: Annotated[
        Optional[str], AfterValidator(_validate_dotted_version)
    ] = Field(default=None, description='PHP minimum acceptable version, e.g. "8.2".')
    python_latest_version: Annotated[
        Optional[str], AfterValidator(_validate_dotted_version)
    ] = Field(
        default=None, description='Python minimum acceptable version, e.g. "3.12".'
    )
    java_latest_version: Annotated[
        Optional[str], AfterValidator(_validate_dotted_version)
    ] = Field(default=None, description='Java minimum acceptable version, e.g. "17".')

    # --- SQL ------------------------------------------------------------
    recommended_minimal_tls_versions: Optional[list[Literal["1.2", "1.3"]]] = Field(
        default=None,
        description="TLS versions accepted on Azure SQL Server.",
    )

    # --- Virtual Machines -----------------------------------------------
    desired_vm_sku_sizes: Optional[list[str]] = None
    vm_backup_min_daily_retention_days: Optional[int] = Field(
        default=None,
        ge=7,
        le=9999,
        description=(
            "Min daily backup retention days. Range: 7..9999 "
            "(Azure Backup hard limit; <7 days defeats DR/ransomware recovery)."
        ),
    )

    # --- API Management threat detection (LLM jacking) -----------------
    apim_threat_detection_llm_jacking_threshold: Optional[float] = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description="Fraction of suspicious actions that triggers the detection.",
    )
    apim_threat_detection_llm_jacking_minutes: Optional[int] = Field(
        default=None,
        ge=5,
        le=43200,
        description=(
            "Lookback window (minutes) for LLM-jacking detection. Range: 5..43200 "
            "(under 5 min the signal is dominated by false positives)."
        ),
    )
    apim_threat_detection_llm_jacking_actions: Optional[list[str]] = None
