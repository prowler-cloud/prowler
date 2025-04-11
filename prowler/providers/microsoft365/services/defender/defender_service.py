from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.providers.microsoft365.lib.service.service import Microsoft365Service
from prowler.providers.microsoft365.microsoft365_provider import Microsoft365Provider


class Defender(Microsoft365Service):
    def __init__(self, provider: Microsoft365Provider):
        super().__init__(provider)
        self.powershell.execute("Connect-ExchangeOnline -Credential $Credential")
        self.malware_policies = self._get_malware_filter_policy()
        self.connection_filter_policy = self._get_connection_filter_policy()

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

    def _get_connection_filter_policy(self):
        logger.info("Microsoft365 - Getting connection filter policy...")
        policy = self.powershell.execute(
            "Get-HostedConnectionFilterPolicy -Identity Default | ConvertTo-Json"
        )
        try:
            connection_filter_policy = ConnectionFilterPolicy(
                ip_allow_list=policy.get("IPAllowList", []),
                identity=policy.get("Identity", ""),
            )

        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        return connection_filter_policy


class DefenderMalwarePolicy(BaseModel):
    enable_file_filter: bool
    identity: str


class ConnectionFilterPolicy(BaseModel):
    ip_allow_list: list
    identity: str
