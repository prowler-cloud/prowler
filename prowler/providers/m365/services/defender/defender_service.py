from typing import List

from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.providers.m365.lib.service.service import M365Service
from prowler.providers.m365.m365_provider import M365Provider


class Defender(M365Service):
    def __init__(self, provider: M365Provider):
        super().__init__(provider)
        self.malware_policies = None
        self.outbound_spam_policies = None
        self.outbound_spam_rules = None
        self.antiphishing_policies = None
        self.antiphising_rules = None
        self.connection_filter_policy = None
        self.dkim_configurations = None

        if self.powershell:
            self.powershell.connect_exchange_online()
            self.malware_policies = self._get_malware_filter_policy()
            self.outbound_spam_policies = self._get_outbound_spam_filter_policy()
            self.outbound_spam_rules = self._get_outbound_spam_filter_rule()
            self.antiphishing_policies = self._get_antiphising_policy()
            self.antiphising_rules = self._get_antiphising_rules()
            self.connection_filter_policy = self._get_connection_filter_policy()
            self.dkim_configurations = self._get_dkim_config()
            self.powershell.close()

    def _get_malware_filter_policy(self):
        logger.info("M365 - Getting Defender malware filter policy...")
        malware_policies = []
        try:
            malware_policy = self.powershell.get_malware_filter_policy()
            if isinstance(malware_policy, dict):
                malware_policy = [malware_policy]
            for policy in malware_policy:
                if policy:
                    malware_policies.append(
                        MalwarePolicy(
                            enable_file_filter=policy.get("EnableFileFilter", True),
                            identity=policy.get("Identity", ""),
                            enable_internal_sender_admin_notifications=policy.get(
                                "EnableInternalSenderAdminNotifications", False
                            ),
                            internal_sender_admin_address=policy.get(
                                "InternalSenderAdminAddress", ""
                            ),
                        )
                    )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        return malware_policies

    def _get_antiphising_policy(self):
        logger.info("Microsoft365 - Getting Defender antiphishing policy...")
        antiphishing_policies = {}
        try:
            antiphishing_policy = self.powershell.get_antiphishing_policy()
            if isinstance(antiphishing_policy, dict):
                antiphishing_policy = [antiphishing_policy]
            for policy in antiphishing_policy:
                if policy:
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
        antiphishing_rules = {}
        try:
            antiphishing_rule = self.powershell.get_antiphishing_rules()
            if isinstance(antiphishing_rule, dict):
                antiphishing_rule = [antiphishing_rule]
            for rule in antiphishing_rule:
                if rule:
                    antiphishing_rules[rule.get("Name", "")] = AntiphishingRule(
                        state=rule.get("State", ""),
                    )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        return antiphishing_rules

    def _get_connection_filter_policy(self):
        logger.info("Microsoft365 - Getting connection filter policy...")
        connection_filter_policy = None
        try:
            policy = self.powershell.get_connection_filter_policy()
            if policy:
                connection_filter_policy = ConnectionFilterPolicy(
                    ip_allow_list=policy.get("IPAllowList", []),
                    identity=policy.get("Identity", ""),
                    enable_safe_list=policy.get("EnableSafeList", False),
                )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        return connection_filter_policy

    def _get_dkim_config(self):
        logger.info("Microsoft365 - Getting DKIM settings...")
        dkim_configs = []
        try:
            dkim_config = self.powershell.get_dkim_config()
            if isinstance(dkim_config, dict):
                dkim_config = [dkim_config]
            for config in dkim_config:
                if config:
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

    def _get_outbound_spam_filter_policy(self):
        logger.info("Microsoft365 - Getting Defender outbound spam filter policy...")
        outbound_spam_policies = {}
        try:
            outbound_spam_policy = self.powershell.get_outbound_spam_filter_policy()
            if isinstance(outbound_spam_policy, dict):
                outbound_spam_policy = [outbound_spam_policy]
            for policy in outbound_spam_policy:
                if policy:
                    outbound_spam_policies[policy.get("Name", "")] = OutboundSpamPolicy(
                        notify_sender_blocked=policy.get("NotifyOutboundSpam", True),
                        notify_limit_exceeded=policy.get(
                            "BccSuspiciousOutboundMail", True
                        ),
                        notify_limit_exceeded_addresses=policy.get(
                            "BccSuspiciousOutboundAdditionalRecipients", []
                        ),
                        notify_sender_blocked_addresses=policy.get(
                            "NotifyOutboundSpamRecipients", []
                        ),
                        default=policy.get("IsDefault", False),
                    )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        return outbound_spam_policies

    def _get_outbound_spam_filter_rule(self):
        logger.info("Microsoft365 - Getting Defender outbound spam filter rule...")
        outbound_spam_rules = {}
        try:
            outbound_spam_rule = self.powershell.get_outbound_spam_filter_rule()
            if isinstance(outbound_spam_rule, dict):
                outbound_spam_rule = [outbound_spam_rule]
            for rule in outbound_spam_rule:
                if rule:
                    outbound_spam_rules[rule.get("Name", "")] = OutboundSpamRule(
                        state=rule.get("State", "Disabled"),
                    )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        return outbound_spam_rules


class MalwarePolicy(BaseModel):
    enable_file_filter: bool
    identity: str
    enable_internal_sender_admin_notifications: bool
    internal_sender_admin_address: str


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


class ConnectionFilterPolicy(BaseModel):
    ip_allow_list: list
    identity: str
    enable_safe_list: bool


class DkimConfig(BaseModel):
    dkim_signing_enabled: bool
    id: str


class OutboundSpamPolicy(BaseModel):
    notify_sender_blocked: bool
    notify_limit_exceeded: bool
    notify_limit_exceeded_addresses: List[str]
    notify_sender_blocked_addresses: List[str]
    default: bool


class OutboundSpamRule(BaseModel):
    state: str
