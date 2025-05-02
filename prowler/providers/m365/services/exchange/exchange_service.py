from enum import Enum
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
        self.transport_config = None
        self.mailbox_policy = None
        self.mailbox_audit_properties = []

        if self.powershell:
            self.powershell.connect_exchange_online()
            self.organization_config = self._get_organization_config()
            self.mailboxes_config = self._get_mailbox_audit_config()
            self.external_mail_config = self._get_external_mail_config()
            self.transport_rules = self._get_transport_rules()
            self.transport_config = self._get_transport_config()
            self.mailbox_policy = self._get_mailbox_policy()
            self.mailbox_audit_properties = self._get_mailbox_audit_properties()
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

    def _get_transport_config(self):
        logger.info("Microsoft365 - Getting transport configuration...")
        transport_config = []
        try:
            transport_configuration = self.powershell.get_transport_config()
            if transport_configuration:
                transport_config = TransportConfig(
                    smtp_auth_disabled=transport_configuration.get(
                        "SmtpClientAuthenticationDisabled", False
                    ),
                )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        return transport_config

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

    def _get_mailbox_audit_properties(self):
        logger.info("Microsoft365 - Getting mailbox audit properties...")
        mailbox_audit_properties = []
        try:
            mailbox_audit_properties_info = (
                self.powershell.get_mailbox_audit_properties()
            )
            if not mailbox_audit_properties_info:
                return mailbox_audit_properties
            if isinstance(mailbox_audit_properties_info, dict):
                mailbox_audit_properties_info = [mailbox_audit_properties_info]
            for mailbox_audit_property in mailbox_audit_properties_info:
                if mailbox_audit_property:
                    mailbox_audit_properties.append(
                        MailboxAuditProperties(
                            name=mailbox_audit_property.get("UserPrincipalName", ""),
                            audit_enabled=mailbox_audit_property.get(
                                "AuditEnabled", False
                            ),
                            audit_admin=mailbox_audit_property.get("AuditAdmin", []),
                            audit_delegate=mailbox_audit_property.get(
                                "AuditDelegate", []
                            ),
                            audit_owner=mailbox_audit_property.get("AuditOwner", []),
                            audit_log_age=int(
                                mailbox_audit_property.get(
                                    "AuditLogAgeLimit", "90.00:00:00"
                                ).split(".")[0]
                            ),
                            identity=mailbox_audit_property.get("Identity", ""),
                        )
                    )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        return mailbox_audit_properties


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


class TransportConfig(BaseModel):
    smtp_auth_disabled: bool


class MailboxPolicy(BaseModel):
    id: str
    additional_storage_enabled: bool


class MailboxAuditProperties(BaseModel):
    name: str
    audit_enabled: bool
    audit_admin: list[str]
    audit_delegate: list[str]
    audit_owner: list[str]
    audit_log_age: int
    identity: str


class AuditAdmin(Enum):
    APPLY_RECORD = "ApplyRecord"
    COPY = "Copy"
    CREATE = "Create"
    FOLDER_BIND = "FolderBind"
    HARD_DELETE = "HardDelete"
    MOVE = "Move"
    MOVE_TO_DELETED_ITEMS = "MoveToDeletedItems"
    SEND_AS = "SendAs"
    SEND_ON_BEHALF = "SendOnBehalf"
    SOFT_DELETE = "SoftDelete"
    UPDATE = "Update"
    UPDATE_CALENDAR_DELEGATION = "UpdateCalendarDelegation"
    UPDATE_FOLDER_PERMISSIONS = "UpdateFolderPermissions"
    UPDATE_INBOX_RULES = "UpdateInboxRules"


class AuditDelegate(Enum):
    APPLY_RECORD = "ApplyRecord"
    CREATE = "Create"
    FOLDER_BIND = "FolderBind"
    HARD_DELETE = "HardDelete"
    MOVE = "Move"
    MOVE_TO_DELETED_ITEMS = "MoveToDeletedItems"
    SEND_AS = "SendAs"
    SEND_ON_BEHALF = "SendOnBehalf"
    SOFT_DELETE = "SoftDelete"
    UPDATE = "Update"
    UPDATE_FOLDER_PERMISSIONS = "UpdateFolderPermissions"
    UPDATE_INBOX_RULES = "UpdateInboxRules"


class AuditOwner(Enum):
    APPLY_RECORD = "ApplyRecord"
    CREATE = "Create"
    HARD_DELETE = "HardDelete"
    MAILBOX_LOGIN = "MailboxLogin"
    MOVE = "Move"
    MOVE_TO_DELETED_ITEMS = "MoveToDeletedItems"
    SOFT_DELETE = "SoftDelete"
    UPDATE = "Update"
    UPDATE_CALENDAR_DELEGATION = "UpdateCalendarDelegation"
    UPDATE_FOLDER_PERMISSIONS = "UpdateFolderPermissions"
    UPDATE_INBOX_RULES = "UpdateInboxRules"
