from typing import Optional

from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.providers.m365.lib.service.service import M365Service
from prowler.providers.m365.m365_provider import M365Provider


class Exchange(M365Service):
    def __init__(self, provider: M365Provider):
        super().__init__(provider)
        self.organization_config = None
        self.mailboxes_config = []
        self.external_mail_config = []
        self.transport_rules = []
        self.mailbox_policy = None

        if self.powershell:
            self.powershell.connect_exchange_online()
            self.organization_config = self._get_organization_config()
            self.mailboxes_config = self._get_mailbox_audit_config()
            self.external_mail_config = self._get_external_mail_config()
            self.transport_rules = self._get_transport_rules()
            self.mailbox_policy = self._get_mailbox_policy()
            self.powershell.close()

    def _get_organization_config(self):
        logger.info("Microsoft365 - Getting Exchange Organization configuration...")
        organization_config = None
        try:
            organization_configuration = self.powershell.get_organization_config()
            if organization_configuration:
                organization_config = Organization(
                    name=organization_configuration.get("Name", ""),
                    guid=organization_configuration.get("Guid", ""),
                    audit_disabled=organization_configuration.get(
                        "AuditDisabled", False
                    ),
                    mailtips_enabled=organization_configuration.get(
                        "MailTipsAllTipsEnabled", True
                    ),
                    mailtips_external_recipient_enabled=organization_configuration.get(
                        "MailTipsExternalRecipientsTipsEnabled", False
                    ),
                    mailtips_group_metrics_enabled=organization_configuration.get(
                        "MailTipsGroupMetricsEnabled", True
                    ),
                    mailtips_large_audience_threshold=organization_configuration.get(
                        "MailTipsLargeAudienceThreshold", 25
                    ),
                )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        return organization_config

    def _get_mailbox_audit_config(self):
        logger.info("Microsoft365 - Getting mailbox audit configuration...")
        mailboxes_config = []
        try:
            mailbox_audit_data = self.powershell.get_mailbox_audit_config()
            for mailbox_audit_config in mailbox_audit_data:
                mailboxes_config.append(
                    MailboxAuditConfig(
                        name=mailbox_audit_config.get("Name", ""),
                        id=mailbox_audit_config.get("Id", ""),
                        audit_bypass_enabled=mailbox_audit_config.get(
                            "AuditBypassEnabled", True
                        ),
                    )
                )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        return mailboxes_config

    def _get_external_mail_config(self):
        logger.info("Microsoft365 - Getting external mail configuration...")
        external_mail_config = []
        try:
            external_mail_configuration = self.powershell.get_external_mail_config()
            if not external_mail_configuration:
                return external_mail_config
            if isinstance(external_mail_configuration, dict):
                external_mail_configuration = [external_mail_configuration]
            for external_mail in external_mail_configuration:
                if external_mail:
                    external_mail_config.append(
                        ExternalMailConfig(
                            identity=external_mail.get("Identity", ""),
                            external_mail_tag_enabled=external_mail.get(
                                "Enabled", False
                            ),
                        )
                    )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        return external_mail_config

    def _get_transport_rules(self):
        logger.info("Microsoft365 - Getting transport rules configuration...")
        transport_rules = []
        try:
            rules_data = self.powershell.get_transport_rules()
            if not rules_data:
                return transport_rules
            if isinstance(rules_data, dict):
                rules_data = [rules_data]
            for rule in rules_data:
                if rule:
                    transport_rules.append(
                        TransportRule(
                            name=rule.get("Name", ""),
                            scl=rule.get("SetSCL", None),
                            sender_domain_is=rule.get("SenderDomainIs", []),
                        )
                    )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        return transport_rules

    def _get_mailbox_policy(self):
        logger.info("Microsoft365 - Getting mailbox policy configuration...")
        mailboxes_policy = None
        try:
            mailbox_policy = self.powershell.get_mailbox_policy()
            if mailbox_policy:
                mailboxes_policy = MailboxPolicy(
                    id=mailbox_policy.get("Id", ""),
                    additional_storage_enabled=mailbox_policy.get(
                        "AdditionalStorageProvidersAvailable", True
                    ),
                )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        return mailboxes_policy


class Organization(BaseModel):
    name: str
    guid: str
    audit_disabled: bool
    mailtips_enabled: bool
    mailtips_external_recipient_enabled: bool
    mailtips_group_metrics_enabled: bool
    mailtips_large_audience_threshold: int


class MailboxAuditConfig(BaseModel):
    name: str
    id: str
    audit_bypass_enabled: bool


class ExternalMailConfig(BaseModel):
    identity: str
    external_mail_tag_enabled: bool


class TransportRule(BaseModel):
    name: str
    scl: Optional[int]
    sender_domain_is: list[str]


class MailboxPolicy(BaseModel):
    id: str
    additional_storage_enabled: bool
