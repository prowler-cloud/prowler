from prowler.lib.logger import logger
from prowler.lib.powershell.powershell import PowerShellSession


def initialize_m365_powershell_modules():
    """
    Initialize required PowerShell modules.

    Checks if the required PowerShell modules are installed and installs them if necessary.
    This method ensures that all required modules for M365 operations are available.

    Returns:
        bool: True if all modules were successfully initialized, False otherwise
    """

    REQUIRED_MODULES = [
        "ExchangeOnlineManagement",
        "MicrosoftTeams",
    ]

    pwsh = PowerShellSession()
    try:
        for module in REQUIRED_MODULES:
            try:
                # Check if module is already installed
                result = pwsh.execute(
                    f"Get-Module -ListAvailable -Name {module}", timeout=5
                )

                # Install module if not installed
                if not result:
                    install_result = pwsh.execute(
                        f'Install-Module -Name "{module}" -Force -AllowClobber -Scope CurrentUser',
                        timeout=30,
                    )
                    if install_result:
                        logger.warning(
                            f"Unexpected output while installing module {module}: {install_result}"
                        )
                    else:
                        logger.info(f"Successfully installed module {module}")

                    # Import module
                    pwsh.execute(f'Import-Module -Name "{module}" -Force', timeout=1)

            except Exception as error:
                logger.error(f"Failed to initialize module {module}: {str(error)}")
                return False

        return True
    finally:
        pwsh.close()


if __name__ == "__main__":
    initialize_m365_powershell_modules()
