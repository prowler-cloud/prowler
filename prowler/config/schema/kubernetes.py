from typing import Optional

from pydantic import Field

from prowler.config.schema.base import ProviderConfigBase


class KubernetesProviderConfig(ProviderConfigBase):
    audit_log_maxbackup: Optional[int] = Field(default=None, gt=0)
    audit_log_maxsize: Optional[int] = Field(default=None, gt=0)
    audit_log_maxage: Optional[int] = Field(default=None, gt=0)
    apiserver_strong_ciphers: Optional[list[str]] = None
    kubelet_strong_ciphers: Optional[list[str]] = None
