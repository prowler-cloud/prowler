from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.providers.microsoft365.lib.service.service import Microsoft365Service
from prowler.providers.microsoft365.microsoft365_provider import Microsoft365Provider


class Defender(Microsoft365Service):
    def __init__(self, provider: Microsoft365Provider):
        super().__init__(provider)
        self.powershell.execute("Connect-ExchangeOnline -Credential $Credential")
        self.malware_policies = self._get_malware_filter_policy()
        self.inbound_spam_policies = self._get_inbound_spam_filter_policy()

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

    def _get_inbound_spam_filter_policy(self):
        logger.info("Microsoft365 - Getting Defender inbound spam filter policy...")
        inbound_spam_policy = self.powershell.execute(
            "Get-HostedContentFilterPolicy | ConvertTo-Json"
        )
        if isinstance(inbound_spam_policy, dict):
            inbound_spam_policy = [inbound_spam_policy]
        inbound_spam_policies = []
        try:
            for policy in inbound_spam_policy:
                inbound_spam_policies.append(
                    DefenderInboundSpamPolicy(
                        identity=policy.get("Identity", ""),
                        allowed_sender_domains=policy.get("AllowedSenderDomains", []),
                    )
                )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        return inbound_spam_policies


class DefenderMalwarePolicy(BaseModel):
    enable_file_filter: bool
    identity: str


class DefenderInboundSpamPolicy(BaseModel):
    identity: str
    allowed_sender_domains: list[str] = []
