from typing import Optional

from prowler.lib.check.models import CheckReportM365
from prowler.lib.logger import logger
from prowler.providers.m365.lib.fix.fixer import M365Fixer
from prowler.providers.m365.services.purview.purview_client import purview_client


class PurviewAuditLogSearchEnabledFixer(M365Fixer):
    """
    Fixer for Purview audit log search.
    This fixer enables the audit log search using PowerShell.
    """

    def __init__(self):
        """
        Initialize Purview audit log search fixer.
        """
        print("Inicializando PurviewAuditLogSearchEnabledFixer")
        super().__init__(
            description="Enable Purview audit log search",
            cost_impact=False,
            cost_description=None,
            service="purview",
        )

    def fix(self, finding: Optional[CheckReportM365] = None, **kwargs) -> bool:
        """
        Enable Purview audit log search using PowerShell.
        This fixer executes the Set-AdminAuditLogConfig cmdlet to enable the audit log search.

        Args:
            finding (Optional[CheckReportM365]): Finding to fix
            **kwargs: Additional arguments

        Returns:
            bool: True if the operation is successful (audit log search is enabled), False otherwise
        """
        try:
            print("Iniciando fix de Purview Audit Log")
            # Show the fixing message
            super().fix()

            print(f"Estado de purview_client: {purview_client}")
            print(f"Estado de purview_client.powershell: {purview_client.powershell}")

            # Connect to Exchange Online
            if purview_client.powershell:
                print("Conectando a Exchange Online")
                purview_client.powershell.connect_exchange_online()
                try:
                    # Execute the command to enable audit log search
                    print("Ejecutando comando pwsh")
                    purview_client.powershell.execute(
                        "Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true"
                    )
                    return True
                finally:
                    # Always close the PowerShell session
                    print("Cerrando sesión de PowerShell")
                    purview_client.powershell.close()
            else:
                logger.error("PowerShell session could not be initialized")
                print("Error al inicializar la sesión de PowerShell")
                return False

        except Exception as error:
            print(f"Error en el fixer: {str(error)}")
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            return False
