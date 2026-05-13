from typing import Literal, Optional

from pydantic import Field

from prowler.config.schema.base import ProviderConfigBase


class AzureProviderConfig(ProviderConfigBase):
    # Network
    shodan_api_key: Optional[str] = None

    # Defender
    defender_attack_path_minimal_risk_level: Optional[
        Literal["Low", "Medium", "High", "Critical"]
    ] = None

    # App Service
    php_latest_version: Optional[str] = None
    python_latest_version: Optional[str] = None
    java_latest_version: Optional[str] = None

    # SQL
    recommended_minimal_tls_versions: Optional[list[str]] = None

    # Virtual Machines
    desired_vm_sku_sizes: Optional[list[str]] = None
    vm_backup_min_daily_retention_days: Optional[int] = Field(default=None, gt=0)

    # API Management threat detection
    apim_threat_detection_llm_jacking_threshold: Optional[float] = Field(
        default=None, ge=0.0, le=1.0
    )
    apim_threat_detection_llm_jacking_minutes: Optional[int] = Field(default=None, gt=0)
    apim_threat_detection_llm_jacking_actions: Optional[list[str]] = None
