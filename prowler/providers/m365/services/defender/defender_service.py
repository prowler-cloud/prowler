from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.providers.m365.lib.service.service import M365Service
from prowler.providers.m365.m365_provider import M365Provider


class Defender(M365Service):
    def __init__(self, provider: M365Provider):
        super().__init__(provider)
        self.powershell.connect_exchange_online()
        self.malware_policies = self._get_malware_filter_policy()
        self.antiphishing_policies = self._get_antiphising_policy()
        self.antiphising_rules = self._get_antiphising_rules()
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

    def _get_antiphising_policy(self):
        logger.info("Microsoft365 - Getting Defender antiphishing policy...")
        antiphishing_policy = self.powershell.get_antiphishing_policy()
        if isinstance(antiphishing_policy, dict):
            antiphishing_policy = [antiphishing_policy]
        antiphishing_policies = {}
        try:
            for policy in antiphishing_policy:
                antiphishing_policies[policy.get("Name", "")] = AntiphishingPolicy(
                    spoof_intelligence=policy.get("EnableSpoofIntelligence", True),
                    spoof_intelligence_action=policy.get(
                        "AuthenticationFailAction", ""
                    ),
                    dmarc_reject_action=policy.get("DmarcRejectAction", ""),
                    dmarc_quarantine_action=policy.get("DmarcQuarantineAction", ""),
                    safety_tips=policy.get("EnableFirstContactSafetyTips", True),
                    unauthenticated_sender_action=policy.get(
                        "EnableUnauthenticatedSender", True
                    ),
                    show_tag=policy.get("EnableViaTag", True),
                    honor_dmarc_policy=policy.get("HonorDmarcPolicy", True),
                    default=policy.get("IsDefault", False),
                )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        return antiphishing_policies

    def _get_antiphising_rules(self):
        logger.info("Microsoft365 - Getting Defender antiphishing rules...")
        antiphishing_rule = self.powershell.get_antiphishing_rules()
        if isinstance(antiphishing_rule, dict):
            antiphishing_rule = [antiphishing_rule]
        antiphishing_rules = {}
        try:
            for rule in antiphishing_rule:
                antiphishing_rules[rule.get("Name", "")] = AntiphishingRule(
                    state=rule.get("State", ""),
                )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        return antiphishing_rules


class DefenderMalwarePolicy(BaseModel):
    enable_file_filter: bool
    identity: str


class AntiphishingPolicy(BaseModel):
    spoof_intelligence: bool
    spoof_intelligence_action: str
    dmarc_reject_action: str
    dmarc_quarantine_action: str
    safety_tips: bool
    unauthenticated_sender_action: bool
    show_tag: bool
    honor_dmarc_policy: bool
    default: bool


class AntiphishingRule(BaseModel):
    state: str
