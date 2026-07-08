"""Fixer for Exchange Online Delicensing Resiliency."""

from prowler.lib.logger import logger
from prowler.providers.common.provider import Provider
from prowler.providers.m365.lib.powershell.m365_powershell import M365PowerShell


def fixer(resource_id: str = "") -> bool:
    """Enable Delicensing Resiliency in Exchange Online.

    Args:
        resource_id (str): Unused for this organization-level fixer.

    Returns:
        bool: True when the fixer command succeeds, False otherwise.
    """
    session = None

    try:
        provider = Provider.get_global_provider()
        if not provider:
            logger.error("Unable to load the global M365 provider for Exchange Online.")
            return False

        credentials = getattr(provider, "credentials", None)
        identity = getattr(provider, "identity", None)
        if not credentials or not identity:
            logger.error(
                "Unable to load the M365 credentials required for Exchange Online."
            )
            return False

        session = M365PowerShell(credentials, identity)
        if not session.connect_exchange_online():
            logger.error("Unable to connect to Exchange Online PowerShell.")
            return False

        result = session.execute(
            "Set-OrganizationConfig -DelayedDelicensingEnabled $true",
            timeout=30,
        )
        if result:
            logger.error(
                "PowerShell execution failed while running "
                '"Set-OrganizationConfig -DelayedDelicensingEnabled $true": '
                f"{result}"
            )
            return False
        return True
    except Exception as error:
        logger.error(
            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
        )
        return False
    finally:
        if session:
            session.close()
