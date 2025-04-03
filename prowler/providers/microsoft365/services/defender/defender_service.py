from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.providers.microsoft365.lib.service.service import Microsoft365Service
from prowler.providers.microsoft365.microsoft365_provider import Microsoft365Provider


class Defender(Microsoft365Service):
    def __init__(self, provider: Microsoft365Provider):
        super().__init__(provider)
        self.powershell.execute("Connect-ExchangeOnline -Credential $Credential")
        self.malware_policy = self._get_malware_filter_policy()

    def _get_malware_filter_policy(self):
        logger.info("Microsoft365 - Getting Defender malware filter policy...")
        malware_policy = self.powershell.execute(
            "Get-MalwareFilterPolicy | ConvertTo-Json"
        )
        try:
            malware_policy = DefenderMalwarePolicy(
                enable_file_filter=malware_policy.get("EnableFileFilter", True)
            )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        return malware_policy


class DefenderMalwarePolicy(BaseModel):
    enable_file_filter: bool
