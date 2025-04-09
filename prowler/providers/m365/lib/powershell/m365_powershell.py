from prowler.lib.powershell.powershell import PowerShellSession
from prowler.providers.m365.models import M365Credentials


class M365PowerShell(PowerShellSession):
    """
    Microsoft 365 specific PowerShell session management implementation.

    This class extends the base PowerShellSession to provide Microsoft 365 specific
    functionality, including authentication, Teams management, and Exchange Online
    operations.

    Features:
    - Microsoft 365 credential management
    - Teams client configuration
    - Exchange Online connectivity
    - Audit log configuration
    - Secure credential handling

    Attributes:
        credentials (M365Credentials): The Microsoft 365 credentials used for authentication.

    Note:
        This class requires the Microsoft Teams and Exchange Online PowerShell modules
        to be installed and available in the PowerShell environment.
    """

    def __init__(self, credentials: M365Credentials):
        """
        Initialize a Microsoft 365 PowerShell session.

        Sets up the PowerShell session and initializes the provided credentials
        for Microsoft 365 authentication.

        Args:
            credentials (M365Credentials): The Microsoft 365 credentials to use
                for authentication.
        """
        super().__init__()
        self.init_credential(credentials)

    def init_credential(self, credentials: M365Credentials) -> None:
        """
        Initialize PowerShell credential object for Microsoft 365 authentication.

        Sanitizes the username and password, then creates a PSCredential object
        in the PowerShell session for use with Microsoft 365 cmdlets.

        Args:
            credentials (M365Credentials): The credentials object containing
                username and password.

        Note:
            The credentials are sanitized to prevent command injection and
            stored securely in the PowerShell session.
        """
        # Sanitize user and password
        user = self.sanitize(credentials.user)
        passwd = self.sanitize(credentials.passwd)

        # Securely convert encrypted password to SecureString
        self.execute(f'$User = "{user}"')
        self.execute(f'$SecureString = "{passwd}" | ConvertTo-SecureString')
        self.execute(
            "$Credential = New-Object System.Management.Automation.PSCredential ($User, $SecureString)"
        )

    def test_credentials(self, credentials: M365Credentials) -> bool:
        """
        Test Microsoft 365 credentials by attempting to connect to Microsoft Teams.

        This method validates the provided credentials by:
        1. Confirming the password is valid by retrieving it from the credential object
        2. Attempting to connect to Microsoft Teams using the credentials

        Args:
            credentials (M365Credentials): The credentials object containing
                username and password to test.

        Returns:
            bool: True if credentials are valid and connection succeeds, False otherwise.
                Specifically returns True if the username appears in the connection output,
                indicating successful authentication.

        Note:
            This method uses PowerShell commands to test the credentials and relies on
            the PowerShell Microsoft Teams module being installed and available.
        """
        # Confirm Password
        self.process.stdin.write("$credential.GetNetworkCredential().Password\n")
        self.process.stdin.write(f"Write-Output '{self.END}'\n")

        if not self.read_output():
            return False

        # Confirm User
        self.process.stdin.write("Connect-MicrosoftTeams -Credential $Credential\n")
        self.process.stdin.write(f"Write-Output '{self.END}'\n")
        return credentials.user in self.read_output()

    def connect_microsoft_teams(self) -> dict:
        """
        Connect to Microsoft Teams Module PowerShell Module.

        Establishes a connection to Microsoft Teams using the initialized credentials.

        Returns:
            dict: Connection status information in JSON format.

        Note:
            This method requires the Microsoft Teams PowerShell module to be installed.
        """
        return self.execute("Connect-MicrosoftTeams -Credential $Credential")

    def get_teams_settings(self) -> dict:
        """
        Get Teams Client Settings.

        Retrieves the current Microsoft Teams client configuration settings.

        Returns:
            dict: Teams client configuration settings in JSON format.

        Example:
            >>> get_teams_settings()
            {
                "AllowBox": true,
                "AllowDropBox": true,
                "AllowGoogleDrive": true
            }
        """
        return self.execute("Get-CsTeamsClientConfiguration | ConvertTo-Json")

    def connect_exchange_online(self) -> dict:
        """
        Connect to Exchange Online PowerShell Module.

        Establishes a connection to Exchange Online using the initialized credentials.

        Returns:
            dict: Connection status information in JSON format.

        Note:
            This method requires the Exchange Online PowerShell module to be installed.
        """
        return self.execute("Connect-ExchangeOnline -Credential $Credential")

    def get_audit_log_config(self) -> dict:
        """
        Get Purview Admin Audit Log Settings.

        Retrieves the current audit log configuration settings for Microsoft Purview.

        Returns:
            dict: Audit log configuration settings in JSON format.

        Example:
            >>> get_audit_log_config()
            {
                "UnifiedAuditLogIngestionEnabled": true
            }
        """
        return self.execute(
            "Get-AdminAuditLogConfig | Select-Object UnifiedAuditLogIngestionEnabled | ConvertTo-Json"
        )
