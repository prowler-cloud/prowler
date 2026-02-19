from typing import List, Optional

from pydantic.v1 import BaseModel

from prowler.lib.logger import logger
from prowler.providers.m365.lib.service.service import M365Service
from prowler.providers.m365.m365_provider import M365Provider


class Defender(M365Service):
    """
    Microsoft Defender for Office 365 service class.

    This class provides methods to retrieve and manage Microsoft Defender for Office 365
    security policies and configurations, including malware filters, spam policies,
    anti-phishing settings, Safe Attachments, Safe Links, ATP (Advanced Threat Protection),
    and Teams protection policies.

    Attributes:
        malware_policies (list): List of malware filter policies.
        outbound_spam_policies (dict): Dictionary of outbound spam filter policies.
        outbound_spam_rules (dict): Dictionary of outbound spam filter rules.
        antiphishing_policies (dict): Dictionary of anti-phishing policies.
        antiphishing_rules (dict): Dictionary of anti-phishing rules.
        connection_filter_policy: Connection filter policy configuration.
        dkim_configurations (list): List of DKIM signing configurations.
        inbound_spam_policies (list): List of inbound spam filter policies.
        inbound_spam_rules (dict): Dictionary of inbound spam filter rules.
        report_submission_policy: Report submission policy configuration.
        safe_attachments_policies (dict): Dictionary of Safe Attachments policies.
        safe_attachments_rules (dict): Dictionary of Safe Attachments rules.
        advanced_threat_protection_policy: Advanced Threat Protection policy configuration.
        safe_links_policies (dict): Dictionary of Safe Links policies.
        safe_links_rules (dict): Dictionary of Safe Links rules.
        teams_protection_policy: Teams protection policy configuration.
    """

    def __init__(self, provider: M365Provider):
        """
        Initialize the Defender service client.

        Args:
            provider: The M365Provider instance for authentication and configuration.
        """
        super().__init__(provider)
        self.malware_policies = []
        self.outbound_spam_policies = {}
        self.outbound_spam_rules = {}
        self.antiphishing_policies = {}
        self.antiphishing_rules = {}
        self.connection_filter_policy = None
        self.dkim_configurations = []
        self.inbound_spam_policies = []
        self.inbound_spam_rules = {}
        self.report_submission_policy = None
        self.safe_attachments_policies = {}
        self.safe_attachments_rules = {}
        self.advanced_threat_protection_policy = None
        self.safe_links_policies = {}
        self.safe_links_rules = {}
        self.teams_protection_policy = None
        if self.powershell:
            if self.powershell.connect_exchange_online():
                self.malware_policies = self._get_malware_filter_policy()
                self.malware_rules = self._get_malware_filter_rule()
                self.outbound_spam_policies = self._get_outbound_spam_filter_policy()
                self.outbound_spam_rules = self._get_outbound_spam_filter_rule()
                self.antiphishing_policies = self._get_antiphishing_policy()
                self.antiphishing_rules = self._get_antiphishing_rules()
                self.connection_filter_policy = self._get_connection_filter_policy()
                self.dkim_configurations = self._get_dkim_config()
                self.inbound_spam_policies = self._get_inbound_spam_filter_policy()
                self.inbound_spam_rules = self._get_inbound_spam_filter_rule()
                self.report_submission_policy = self._get_report_submission_policy()
                self.safe_attachments_policies = self._get_safe_attachments_policies()
                self.safe_attachments_rules = self._get_safe_attachments_rules()
                self.advanced_threat_protection_policy = (
                    self._get_advanced_threat_protection_policy()
                )
                self.safe_links_policies = self._get_safe_links_policy()
                self.safe_links_rules = self._get_safe_links_rule()
                self.teams_protection_policy = self._get_teams_protection_policy()
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
                    file_types_raw = policy.get("FileTypes", [])
                    file_types = []
                    if file_types_raw is not None:
                        if isinstance(file_types_raw, list):
                            file_types = file_types_raw
                        else:
                            try:
                                if isinstance(file_types_raw, str):
                                    file_types = [file_types_raw]
                                else:
                                    file_types = [str(file_types_raw)]
                            except (ValueError, TypeError):
                                logger.warning(
                                    f"Skipping invalid file_types value: {file_types_raw}"
                                )
                                file_types = []

                    malware_policies.append(
                        MalwarePolicy(
                            enable_file_filter=policy.get("EnableFileFilter", False),
                            identity=policy.get("Identity", ""),
                            enable_internal_sender_admin_notifications=policy.get(
                                "EnableInternalSenderAdminNotifications", False
                            ),
                            internal_sender_admin_address=policy.get(
                                "InternalSenderAdminAddress", ""
                            ),
                            file_types=file_types,
                            is_default=policy.get("IsDefault", False),
                        )
                    )
                    malware_policies.sort(key=lambda x: x.is_default, reverse=True)
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        return malware_policies

    def _get_malware_filter_rule(self):
        logger.info("Microsoft365 - Getting Defender malware filter rule...")
        malware_rules = {}
        try:
            malware_rule = self.powershell.get_malware_filter_rule()
            if isinstance(malware_rule, dict):
                malware_rule = [malware_rule]
            for rule in malware_rule:
                if rule:
                    malware_rules[rule.get("MalwareFilterPolicy", "")] = MalwareRule(
                        state=rule.get("State", ""),
                        priority=rule.get("Priority", 0),
                        users=rule.get("SentTo", None),
                        groups=rule.get("SentToMemberOf", None),
                        domains=rule.get("RecipientDomainIs", None),
                    )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        return malware_rules

    def _get_antiphishing_policy(self):
        logger.info("Microsoft365 - Getting Defender antiphishing policy...")
        antiphishing_policies = {}
        try:
            antiphishing_policy = self.powershell.get_antiphishing_policy()
            if isinstance(antiphishing_policy, dict):
                antiphishing_policy = [antiphishing_policy]
            for policy in antiphishing_policy:
                if policy:
                    antiphishing_policies[policy.get("Name", "")] = AntiphishingPolicy(
                        name=policy.get("Name", ""),
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

                    antiphishing_policies = dict(
                        sorted(
                            antiphishing_policies.items(),
                            key=lambda item: item[1].default,
                            reverse=True,
                        )
                    )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        return antiphishing_policies

    def _get_antiphishing_rules(self):
        logger.info("Microsoft365 - Getting Defender antiphishing rules...")
        antiphishing_rules = {}
        try:
            antiphishing_rule = self.powershell.get_antiphishing_rules()
            if isinstance(antiphishing_rule, dict):
                antiphishing_rule = [antiphishing_rule]
            for rule in antiphishing_rule:
                if rule:
                    antiphishing_rules[rule.get("AntiPhishPolicy", "")] = (
                        AntiphishingRule(
                            state=rule.get("State", ""),
                            priority=rule.get("Priority", 0),
                            users=rule.get("SentTo", None),
                            groups=rule.get("SentToMemberOf", None),
                            domains=rule.get("RecipientDomainIs", None),
                        )
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
                        name=policy.get("Name", ""),
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
                        auto_forwarding_mode=policy.get("AutoForwardingMode", "On"),
                        default=policy.get("IsDefault", False),
                    )

                    outbound_spam_policies = dict(
                        sorted(
                            outbound_spam_policies.items(),
                            key=lambda item: item[1].default,
                            reverse=True,
                        )
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
                    outbound_spam_rules[
                        rule.get("HostedOutboundSpamFilterPolicy", "")
                    ] = OutboundSpamRule(
                        state=rule.get("State", "Disabled"),
                        priority=rule.get("Priority", 0),
                        users=rule.get("From", None),
                        groups=rule.get("FromMemberOf", None),
                        domains=rule.get("SenderDomainIs", None),
                    )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        return outbound_spam_rules

    def _get_inbound_spam_filter_policy(self):
        logger.info("Microsoft365 - Getting Defender inbound spam filter policy...")
        inbound_spam_policies = []
        try:
            inbound_spam_policy = self.powershell.get_inbound_spam_filter_policy()
            if not inbound_spam_policy:
                return inbound_spam_policies
            if isinstance(inbound_spam_policy, dict):
                inbound_spam_policy = [inbound_spam_policy]
            for policy in inbound_spam_policy:
                if policy:
                    allowed_domains_raw = policy.get("AllowedSenderDomains", [])
                    allowed_domains = []

                    if isinstance(allowed_domains_raw, str):
                        try:
                            import json

                            parsed_domains = json.loads(allowed_domains_raw)
                            if isinstance(parsed_domains, list):
                                allowed_domains_raw = parsed_domains
                            else:
                                logger.warning(
                                    f"Expected list from JSON string, got: {type(parsed_domains)}"
                                )
                                allowed_domains_raw = []
                        except (json.JSONDecodeError, ValueError) as e:
                            logger.warning(
                                f"Failed to parse AllowedSenderDomains as JSON: {e}"
                            )
                            allowed_domains_raw = []

                    if allowed_domains_raw:
                        for domain in allowed_domains_raw:
                            if isinstance(domain, str):
                                allowed_domains.append(domain)
                            else:
                                try:
                                    allowed_domains.append(str(domain))
                                except (ValueError, TypeError):
                                    logger.warning(
                                        f"Skipping invalid domain value: {domain}"
                                    )

                    inbound_spam_policies.append(
                        DefenderInboundSpamPolicy(
                            identity=policy.get("Identity", ""),
                            allowed_sender_domains=allowed_domains,
                            default=policy.get("IsDefault", False),
                        )
                    )
                    inbound_spam_policies.sort(key=lambda x: x.default, reverse=True)
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        return inbound_spam_policies

    def _get_inbound_spam_filter_rule(self):
        logger.info("Microsoft365 - Getting Defender inbound spam filter rule...")
        inbound_spam_rules = {}
        try:
            inbound_spam_rule = self.powershell.get_inbound_spam_filter_rule()
            if isinstance(inbound_spam_rule, dict):
                inbound_spam_rule = [inbound_spam_rule]
            for rule in inbound_spam_rule:
                if rule:
                    inbound_spam_rules[rule.get("HostedContentFilterPolicy", "")] = (
                        InboundSpamRule(
                            state=rule.get("State", "Disabled"),
                            priority=rule.get("Priority", 0),
                            users=rule.get("SentTo", None),
                            groups=rule.get("SentToMemberOf", None),
                            domains=rule.get("RecipientDomainIs", None),
                        )
                    )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        return inbound_spam_rules

    def _get_report_submission_policy(self):
        """
        Get the Defender report submission policy.

        Returns:
            ReportSubmissionPolicy: The report submission policy configuration or None.
        """
        logger.info("Microsoft365 - Getting Defender report submission policy...")
        report_submission_policy = None
        try:
            report_submission_policy = self.powershell.get_report_submission_policy()
            if report_submission_policy:
                report_submission_policy = ReportSubmissionPolicy(
                    report_junk_to_customized_address=report_submission_policy.get(
                        "ReportJunkToCustomizedAddress", True
                    ),
                    report_not_junk_to_customized_address=report_submission_policy.get(
                        "ReportNotJunkToCustomizedAddress", True
                    ),
                    report_phish_to_customized_address=report_submission_policy.get(
                        "ReportPhishToCustomizedAddress", True
                    ),
                    report_junk_addresses=report_submission_policy.get(
                        "ReportJunkAddresses", []
                    ),
                    report_not_junk_addresses=report_submission_policy.get(
                        "ReportNotJunkAddresses", []
                    ),
                    report_phish_addresses=report_submission_policy.get(
                        "ReportPhishAddresses", []
                    ),
                    report_chat_message_enabled=report_submission_policy.get(
                        "ReportChatMessageEnabled", True
                    ),
                    report_chat_message_to_customized_address_enabled=report_submission_policy.get(
                        "ReportChatMessageToCustomizedAddressEnabled", True
                    ),
                )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        return report_submission_policy

    def _get_safe_attachments_policies(self):
        """
        Retrieve Safe Attachments policies from Microsoft Defender for Office 365.

        Returns:
            dict[str, SafeAttachmentsPolicy]: A dictionary of Safe Attachments policies keyed by name.
        """
        logger.info("Microsoft365 - Getting Defender Safe Attachments policies...")
        safe_attachments_policies = {}
        try:
            policies_data = self.powershell.get_safe_attachments_policy()
            if not policies_data:
                return safe_attachments_policies
            if isinstance(policies_data, dict):
                policies_data = [policies_data]
            for policy in policies_data:
                if policy:
                    policy_name = policy.get("Name", "")
                    is_built_in = policy_name == "Built-In Protection Policy"
                    safe_attachments_policies[policy_name] = SafeAttachmentsPolicy(
                        name=policy_name,
                        identity=policy.get("Identity", ""),
                        enable=policy.get("Enable", False),
                        action=policy.get("Action", ""),
                        quarantine_tag=policy.get("QuarantineTag", ""),
                        redirect=policy.get("Redirect", False),
                        redirect_address=policy.get("RedirectAddress", ""),
                        is_built_in_protection=is_built_in,
                    )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        return safe_attachments_policies

    def _get_safe_attachments_rules(self):
        """
        Retrieve Safe Attachments rules from Microsoft Defender for Office 365.

        Returns:
            dict[str, SafeAttachmentsRule]: A dictionary of Safe Attachments rules keyed by policy name.
        """
        logger.info("Microsoft365 - Getting Defender Safe Attachments rules...")
        safe_attachments_rules = {}
        try:
            rules_data = self.powershell.get_safe_attachments_rule()
            if not rules_data:
                return safe_attachments_rules
            if isinstance(rules_data, dict):
                rules_data = [rules_data]
            for rule in rules_data:
                if rule:
                    policy_name = rule.get("SafeAttachmentPolicy", "")
                    safe_attachments_rules[policy_name] = SafeAttachmentsRule(
                        state=rule.get("State", ""),
                        priority=rule.get("Priority", 0),
                        users=rule.get("SentTo"),
                        groups=rule.get("SentToMemberOf"),
                        domains=rule.get("RecipientDomainIs"),
                    )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        return safe_attachments_rules

    def _get_advanced_threat_protection_policy(self):
        """
        Get the Advanced Threat Protection policy.

        Retrieves the ATP policy settings including Safe Attachments for SharePoint,
        OneDrive, and Teams, as well as Safe Documents configuration.

        Returns:
            AdvancedThreatProtectionPolicy: The Advanced Threat Protection policy configuration.
        """
        logger.info("Microsoft365 - Getting Advanced Threat Protection policy...")
        atp_policy = None
        try:
            policy = self.powershell.get_advanced_threat_protection_policy()
            if policy:
                atp_policy = AdvancedThreatProtectionPolicy(
                    identity=policy.get("Identity", "Default"),
                    enable_atp_for_spo_teams_odb=policy.get(
                        "EnableATPForSPOTeamsODB", False
                    ),
                    enable_safe_docs=policy.get("EnableSafeDocs", False),
                    allow_safe_docs_open=policy.get("AllowSafeDocsOpen", True),
                )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        return atp_policy

    def _get_safe_links_policy(self):
        """
        Get Safe Links policies from Microsoft Defender for Office 365.

        Returns:
            dict: A dictionary mapping policy names to SafeLinksPolicy objects.
        """
        logger.info("Microsoft365 - Getting Defender Safe Links policies...")
        safe_links_policies = {}
        try:
            safe_links_policy_data = self.powershell.get_safe_links_policy()
            if not safe_links_policy_data:
                return safe_links_policies
            if isinstance(safe_links_policy_data, dict):
                safe_links_policy_data = [safe_links_policy_data]
            for policy in safe_links_policy_data:
                if policy:
                    safe_links_policies[policy.get("Name", "")] = SafeLinksPolicy(
                        name=policy.get("Name", ""),
                        identity=policy.get("Identity", ""),
                        enable_safe_links_for_email=policy.get(
                            "EnableSafeLinksForEmail", False
                        ),
                        enable_safe_links_for_teams=policy.get(
                            "EnableSafeLinksForTeams", False
                        ),
                        enable_safe_links_for_office=policy.get(
                            "EnableSafeLinksForOffice", False
                        ),
                        track_clicks=policy.get("TrackClicks", False),
                        allow_click_through=policy.get("AllowClickThrough", True),
                        scan_urls=policy.get("ScanUrls", False),
                        enable_for_internal_senders=policy.get(
                            "EnableForInternalSenders", False
                        ),
                        deliver_message_after_scan=policy.get(
                            "DeliverMessageAfterScan", False
                        ),
                        disable_url_rewrite=policy.get("DisableUrlRewrite", True),
                        is_built_in_protection=policy.get("IsBuiltInProtection", False),
                        is_default=policy.get("IsDefault", False),
                    )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        return safe_links_policies

    def _get_safe_links_rule(self):
        """
        Get Safe Links rules from Microsoft Defender for Office 365.

        Returns:
            dict: A dictionary mapping policy names to SafeLinksRule objects.
        """
        logger.info("Microsoft365 - Getting Defender Safe Links rules...")
        safe_links_rules = {}
        try:
            safe_links_rule_data = self.powershell.get_safe_links_rule()
            if not safe_links_rule_data:
                return safe_links_rules
            if isinstance(safe_links_rule_data, dict):
                safe_links_rule_data = [safe_links_rule_data]
            for rule in safe_links_rule_data:
                if rule:
                    safe_links_rules[rule.get("SafeLinksPolicy", "")] = SafeLinksRule(
                        state=rule.get("State", "Disabled"),
                        priority=rule.get("Priority", 0),
                        users=rule.get("SentTo", None),
                        groups=rule.get("SentToMemberOf", None),
                        domains=rule.get("RecipientDomainIs", None),
                    )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        return safe_links_rules

    def _get_teams_protection_policy(self):
        """
        Retrieve the Teams protection policy including ZAP settings.

        Returns:
            TeamsProtectionPolicy: The Teams protection policy configuration.
        """
        logger.info("Microsoft365 - Getting Teams protection policy...")
        teams_protection_policy = None
        try:
            policy = self.powershell.get_teams_protection_policy()
            if policy:
                teams_protection_policy = TeamsProtectionPolicy(
                    identity=policy.get("Identity", ""),
                    zap_enabled=policy.get("ZapEnabled", True),
                )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        return teams_protection_policy


class MalwarePolicy(BaseModel):
    enable_file_filter: bool
    identity: str
    enable_internal_sender_admin_notifications: bool
    internal_sender_admin_address: str
    file_types: list[str]
    is_default: bool


class MalwareRule(BaseModel):
    state: str
    priority: int
    users: Optional[list[str]]
    groups: Optional[list[str]]
    domains: Optional[list[str]]


class AntiphishingPolicy(BaseModel):
    name: str
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
    priority: int
    users: Optional[list[str]]
    groups: Optional[list[str]]
    domains: Optional[list[str]]


class ConnectionFilterPolicy(BaseModel):
    ip_allow_list: list
    identity: str
    enable_safe_list: bool


class DkimConfig(BaseModel):
    dkim_signing_enabled: bool
    id: str


class OutboundSpamPolicy(BaseModel):
    name: str
    notify_sender_blocked: bool
    notify_limit_exceeded: bool
    notify_limit_exceeded_addresses: List[str]
    notify_sender_blocked_addresses: List[str]
    auto_forwarding_mode: str
    default: bool


class OutboundSpamRule(BaseModel):
    state: str
    priority: int
    users: Optional[list[str]]
    groups: Optional[list[str]]
    domains: Optional[list[str]]


class DefenderInboundSpamPolicy(BaseModel):
    identity: str
    allowed_sender_domains: list[str] = []
    default: bool


class InboundSpamRule(BaseModel):
    state: str
    priority: int
    users: Optional[list[str]]
    groups: Optional[list[str]]
    domains: Optional[list[str]]


class ReportSubmissionPolicy(BaseModel):
    """Model for Defender report submission policy configuration."""

    report_junk_to_customized_address: bool
    report_not_junk_to_customized_address: bool
    report_phish_to_customized_address: bool
    report_junk_addresses: list[str]
    report_not_junk_addresses: list[str]
    report_phish_addresses: list[str]
    report_chat_message_enabled: bool
    report_chat_message_to_customized_address_enabled: bool


class SafeAttachmentsPolicy(BaseModel):
    """
    Data model for Safe Attachments policy settings.

    Attributes:
        name: The name of the policy.
        identity: The unique identifier of the policy.
        enable: Whether the policy is enabled.
        action: The action to take on malicious attachments (Allow, Block, Replace, DynamicDelivery).
        quarantine_tag: The quarantine policy applied to detected messages.
        redirect: Whether to redirect messages with detected attachments.
        redirect_address: The email address to redirect messages to.
        is_built_in_protection: Whether this is the Built-in Protection Policy.
    """

    name: str
    identity: str
    enable: bool
    action: str
    quarantine_tag: str
    redirect: bool
    redirect_address: str
    is_built_in_protection: bool = False


class SafeAttachmentsRule(BaseModel):
    """
    Data model for Safe Attachments rule settings.

    Attributes:
        state: The state of the rule (Enabled/Disabled).
        priority: The priority of the rule (0 is highest).
        users: List of users the rule applies to.
        groups: List of groups the rule applies to.
        domains: List of domains the rule applies to.
    """

    state: str
    priority: int
    users: Optional[list[str]]
    groups: Optional[list[str]]
    domains: Optional[list[str]]


class AdvancedThreatProtectionPolicy(BaseModel):
    """
    Model for Advanced Threat Protection policy.

    Attributes:
        identity: The identity of the ATP policy.
        enable_atp_for_spo_teams_odb: Whether Safe Attachments is enabled for
            SharePoint, OneDrive, and Microsoft Teams.
        enable_safe_docs: Whether Safe Documents is enabled for clients in Protected View.
        allow_safe_docs_open: Whether users can click through Protected View
            even if Safe Documents identifies the file as malicious.
    """

    identity: str
    enable_atp_for_spo_teams_odb: bool
    enable_safe_docs: bool
    allow_safe_docs_open: bool


class SafeLinksPolicy(BaseModel):
    """Model for Defender Safe Links Policy configuration."""

    name: str
    identity: str
    enable_safe_links_for_email: bool
    enable_safe_links_for_teams: bool
    enable_safe_links_for_office: bool
    track_clicks: bool
    allow_click_through: bool
    scan_urls: bool
    enable_for_internal_senders: bool
    deliver_message_after_scan: bool
    disable_url_rewrite: bool
    is_built_in_protection: bool
    is_default: bool


class SafeLinksRule(BaseModel):
    """Model for Defender Safe Links Rule configuration."""

    state: str
    priority: int
    users: Optional[list[str]]
    groups: Optional[list[str]]
    domains: Optional[list[str]]


class TeamsProtectionPolicy(BaseModel):
    """Model for Teams protection policy settings including ZAP configuration."""

    identity: str
    zap_enabled: bool
