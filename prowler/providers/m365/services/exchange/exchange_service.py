from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.providers.m365.lib.service.service import M365Service
from prowler.providers.m365.m365_provider import M365Provider


class Exchange(M365Service):
    def __init__(self, provider: M365Provider):
        super().__init__(provider)
        self.powershell.connect_exchange_online()
        self.organization_config = self._get_organization_config()
        self.mailboxes_config = self._get_mailbox_audit_config()
        self.external_mail_config = self._get_external_mail_config()
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


class Organization(BaseModel):
    name: str
    guid: str
    audit_disabled: bool


class MailboxAuditConfig(BaseModel):
    name: str
    id: str
    audit_bypass_enabled: bool


class ExternalMailConfig(BaseModel):
    identity: str
    external_mail_tag_enabled: bool
