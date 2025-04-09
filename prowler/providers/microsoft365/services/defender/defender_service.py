from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.providers.microsoft365.lib.service.service import Microsoft365Service
from prowler.providers.microsoft365.microsoft365_provider import Microsoft365Provider


class Defender(Microsoft365Service):
    def __init__(self, provider: Microsoft365Provider):
        super().__init__(provider)
        self.powershell.execute("Connect-ExchangeOnline -Credential $Credential")
        self.malware_policies = self._get_malware_filter_policy()
        self.dkim_configurations = self._get_dkim_config()

    def _get_malware_filter_policy(self):
        logger.info("Microsoft365 - Getting Defender malware filter policy...")
        malware_policy = self.powershell.execute(
            "Get-MalwareFilterPolicy | ConvertTo-Json"
        )
        if isinstance(malware_policy, dict):
            malware_policy = [malware_policy]
        malware_policies = []
        try:
            for policy in malware_policy:
                malware_policies.append(
                    DefenderMalwarePolicy(
                        enable_file_filter=policy.get("EnableFileFilter", True),
                        identity=policy.get("Identity", ""),
                    )
                )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        return malware_policies

    def _get_dkim_config(self):
        logger.info("Microsoft365 - Getting DKIM settings...")
        dkim_config = self.powershell.execute("Get-DkimSigningConfig | ConvertTo-Json")
        if isinstance(dkim_config, dict):
            dkim_config = [dkim_config]
        dkim_configs = []
        try:
            for config in dkim_config:
                dkim_configs.append(
                    DkimConfig(
                        dkim_signing_enabled=config.get("Enabled", False),
                        id=config.get("Id", ""),
                    )
                )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        return dkim_configs


class DefenderMalwarePolicy(BaseModel):
    enable_file_filter: bool
    identity: str


class DkimConfig(BaseModel):
    dkim_signing_enabled: bool
    id: str
