from typing import List

from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.providers.m365.lib.service.service import M365Service
from prowler.providers.m365.m365_provider import M365Provider


class Defender(M365Service):
    def __init__(self, provider: M365Provider):
        super().__init__(provider)
        self.powershell.connect_exchange_online()
        self.malware_policies = self._get_malware_filter_policy()
        self.outbound_spam_policies = self._get_outbound_spam_filter_policy()
        self.outbound_spam_rules = self._get_outbound_spam_filter_rule()
        self.powershell.close()

    def _get_malware_filter_policy(self):
        logger.info("M365 - Getting Defender malware filter policy...")
        malware_policy = self.powershell.get_malware_filter_policy()
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

    def _get_outbound_spam_filter_policy(self):
        logger.info("Microsoft365 - Getting Defender outbound spam filter policy...")
        outbound_spam_policy = self.powershell.get_outbound_spam_filter_policy()
        if isinstance(outbound_spam_policy, dict):
            outbound_spam_policy = [outbound_spam_policy]
        outbound_spam_policies = {}
        try:
            for policy in outbound_spam_policy:
                outbound_spam_policies[policy.get("Name", "")] = (
                    DefenderOutboundSpamPolicy(
                        notify_sender_blocked=policy.get("NotifyOutboundSpam", True),
                        notify_limit_exceeded=policy.get(
                            "BccSuspiciousOutboundMail", True
                        ),
                        notify_limit_exceeded_adresses=policy.get(
                            "BccSuspiciousOutboundAdditionalRecipients", []
                        ),
                        notify_sender_blocked_adresses=policy.get(
                            "NotifyOutboundSpamRecipients", []
                        ),
                        default=policy.get("IsDefault", False),
                    )
                )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        return outbound_spam_policies

    def _get_outbound_spam_filter_rule(self):
        logger.info("Microsoft365 - Getting Defender outbound spam filter rule...")
        outbound_spam_rule = self.powershell.get_outbound_spam_filter_rule()
        if isinstance(outbound_spam_rule, dict):
            outbound_spam_rule = [outbound_spam_rule]
        outbound_spam_rules = {}
        try:
            for rule in outbound_spam_rule:
                outbound_spam_rules[rule.get("Name", "")] = DefenderOutboundSpamRule(
                    state=rule.get("State", "Disabled"),
                )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        return outbound_spam_rules


class DefenderMalwarePolicy(BaseModel):
    enable_file_filter: bool
    identity: str


class DefenderOutboundSpamPolicy(BaseModel):
    notify_sender_blocked: bool
    notify_limit_exceeded: bool
    notify_limit_exceeded_adresses: List[str]
    notify_sender_blocked_adresses: List[str]
    default: bool


class DefenderOutboundSpamRule(BaseModel):
    state: str
