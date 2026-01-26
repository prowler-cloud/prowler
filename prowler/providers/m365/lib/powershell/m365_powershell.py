import os

from prowler.lib.logger import logger
from prowler.lib.powershell.powershell import PowerShellSession
from prowler.providers.m365.exceptions.exceptions import M365CertificateCreationError
from prowler.providers.m365.lib.jwt.jwt_decoder import decode_msal_token
from prowler.providers.m365.models import M365Credentials, M365IdentityInfo


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
        required_modules (list): List of required PowerShell modules for M365 operations.

    Note:
        This class requires the Microsoft Teams and Exchange Online PowerShell modules
        to be installed and available in the PowerShell environment.
    """

    def __init__(self, credentials: M365Credentials, identity: M365IdentityInfo):
        """
        Initialize a Microsoft 365 PowerShell session.

        Sets up the PowerShell session and initializes the provided credentials
        for Microsoft 365 authentication.

        Args:
            credentials (M365Credentials): The Microsoft 365 credentials to use
                for authentication.
        """
        super().__init__()
        self.tenant_identity = identity
        self.init_credential(credentials)

    def clean_certificate_content(self, cert_content: str) -> str:
        """
        Clean certificate content for PowerShell consumption.

        Removes newlines, carriage returns, and extra spaces from base64 content
        to ensure proper parsing in PowerShell.

        Args:
            cert_content (str): Base64 encoded certificate content

        Returns:
            str: Cleaned base64 certificate content
        """
        # Clean base64 content - remove any newlines or whitespace
        clean_content = (
            cert_content.strip().replace("\n", "").replace("\r", "").replace(" ", "")
        )
        logger.info(f"Cleaned certificate content length: {len(clean_content)}")
        return clean_content

    def init_credential(self, credentials: M365Credentials) -> None:
        """
        Initialize PowerShell credential object for Microsoft 365 authentication.

        Supports two authentication methods:
        1. Application authentication (client_id/client_secret)
        2. Certificate authentication (certificate_content in base64/client_id)

        Args:
            credentials (M365Credentials): The credentials object containing
                authentication information.

        Note:
            The credentials are sanitized to prevent command injection and
            stored securely in the PowerShell session.
        """
        # Certificate Auth
        if credentials.certificate_content and credentials.client_id:
            # Clean certificate content for PowerShell consumption
            clean_cert_content = self.clean_certificate_content(
                credentials.certificate_content
            )

            # Sanitize credentials
            sanitized_client_id = self.sanitize(credentials.client_id)
            sanitized_tenant_id = self.sanitize(credentials.tenant_id)

            self.execute(
                f'$certBytes = [Convert]::FromBase64String("{clean_cert_content}")'
            )
            error = self.execute(
                "$certificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(,$certBytes)"
            )
            if error:
                raise M365CertificateCreationError(
                    f"[{os.path.basename(__file__)}] Error creating certificate: {error}"
                )

            self.execute(f'$clientID = "{sanitized_client_id}"')
            self.execute(f'$tenantID = "{sanitized_tenant_id}"')
            self.execute(f'$tenantDomain = "{credentials.tenant_domains[0]}"')

        else:
            # Application Auth
            self.execute(f'$clientID = "{credentials.client_id}"')
            self.execute(f'$clientSecret = "{credentials.client_secret}"')
            self.execute(f'$tenantID = "{credentials.tenant_id}"')
            self.execute(
                '$graphtokenBody = @{ Grant_Type = "client_credentials"; Scope = "https://graph.microsoft.com/.default"; Client_Id = $clientID; Client_Secret = $clientSecret }'
            )
            self.execute(
                '$graphToken = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$tenantID/oauth2/v2.0/token" -Method POST -Body $graphtokenBody | Select-Object -ExpandProperty Access_Token'
            )

    def execute_connect(self, command: str) -> str:
        """
        Execute a PowerShell connect command ensuring empty responses surface as timeouts.

        Args:
            command (str): PowerShell connect command to run.
            timeout (Optional[int]): Timeout in seconds for the command execution.

        Returns:
            str: Command output or 'Timeout' if the command produced no output.
        """
        connect_timeout = 15
        result = self.execute(command, timeout=connect_timeout)
        return result or "'execute_connect' command timeout reached"

    def test_teams_connection(self) -> bool:
        """Test Microsoft Teams API connection and raise exception if it fails."""
        try:
            self.execute(
                '$teamstokenBody = @{ Grant_Type = "client_credentials"; Scope = "48ac35b8-9aa8-4d74-927d-1f4a14a0b239/.default"; Client_Id = $clientID; Client_Secret = $clientSecret }'
            )
            result = self.execute(
                '$teamsToken = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$tenantID/oauth2/v2.0/token" -Method POST -Body $teamstokenBody | Select-Object -ExpandProperty Access_Token'
            )
            if result != "":
                logger.error(f"Microsoft Teams connection failed: {result}")
                return False
            self.execute_connect(
                'Connect-MicrosoftTeams -AccessTokens @("$graphToken","$teamsToken")'
            )
            return True
        except Exception as e:
            logger.error(
                f"Microsoft Teams connection failed: {e}. Please check your permissions and try again."
            )
            return False

    def test_teams_certificate_connection(self) -> bool:
        """Test Microsoft Teams API connection using certificate and raise exception if it fails."""
        result = self.execute_connect(
            "Connect-MicrosoftTeams -Certificate $certificate -ApplicationId $clientID -TenantId $tenantID"
        )
        if self.tenant_identity.identity_id not in result:
            logger.error(f"Microsoft Teams Certificate connection failed: {result}")
            return False
        return True

    def test_exchange_connection(self) -> bool:
        """Test Exchange Online API connection and raise exception if it fails."""
        try:
            self.execute(
                '$SecureSecret = ConvertTo-SecureString "$clientSecret" -AsPlainText -Force'
            )
            self.execute(
                '$exchangeToken = Get-MsalToken -clientID "$clientID" -tenantID "$tenantID" -clientSecret $SecureSecret -Scopes "https://outlook.office365.com/.default"'
            )
            token = decode_msal_token(self.execute("Write-Output $exchangeToken"))
            permissions = token.get("roles", [])
            if "Exchange.ManageAsApp" not in permissions:
                logger.error(
                    "Exchange Online connection failed: Please check your permissions and try again."
                )
                return False
            self.execute_connect(
                'Connect-ExchangeOnline -AccessToken $exchangeToken.AccessToken -Organization "$tenantID"'
            )
            return True
        except Exception as e:
            logger.error(
                f"Exchange Online connection failed: {e}. Please check your permissions and try again."
            )
            return False

    def test_exchange_certificate_connection(self) -> bool:
        """Test Exchange Online API connection using certificate and raise exception if it fails."""
        result = self.execute_connect(
            "Connect-ExchangeOnline -Certificate $certificate -AppId $clientID -Organization $tenantDomain"
        )
        if "https://aka.ms/exov3-module" not in result:
            logger.error(f"Exchange Online Certificate connection failed: {result}")
            return False
        return True

    def connect_microsoft_teams(self) -> dict:
        """
        Connect to Microsoft Teams Module PowerShell Module.

        Establishes a connection to Microsoft Teams using the initialized credentials.
        Supports two authentication methods:
        1. Application authentication (client_id/client_secret)
        2. Certificate authentication (certificate_content in base64/client_id)

        Returns:
            dict: Connection status information in JSON format.

        Note:
            This method requires the Microsoft Teams PowerShell module to be installed.
        """
        # Certificate Auth
        if self.execute("Write-Output $certificate") != "":
            return self.test_teams_certificate_connection()
        # Application Auth
        return self.test_teams_connection()

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
        return self.execute(
            "Get-CsTeamsClientConfiguration | ConvertTo-Json -Depth 10",
            json_parse=True,
        )

    def get_global_meeting_policy(self) -> dict:
        """
        Get Teams Global Meeting Policy.

        Retrieves the current Microsoft Teams global meeting policy settings.

        Returns:
            dict: Teams global meeting policy settings in JSON format.

        Example:
            >>> get_global_meeting_policy()
            {
                "AllowAnonymousUsersToJoinMeeting": true
            }
        """
        return self.execute(
            "Get-CsTeamsMeetingPolicy -Identity Global | ConvertTo-Json -Depth 10",
            json_parse=True,
        )

    def get_global_messaging_policy(self) -> dict:
        """
        Get Teams Global Messaging Policy.

        Retrieves the current Microsoft Teams global messaging policy settings.

        Returns:
            dict: Teams global messaging policy settings in JSON format.

        Example:
            >>> get_global_meeting_policy()
            {
                "AllowAnonymousUsersToJoinMeeting": true
            }
        """
        return self.execute(
            "Get-CsTeamsMessagingPolicy -Identity Global | ConvertTo-Json -Depth 10",
            json_parse=True,
        )

    def get_user_settings(self) -> dict:
        """
        Get Teams User Settings.

        Retrieves the current Microsoft Teams user settings.

        Returns:
            dict: Teams user settings in JSON format.

        Example:
            >>> get_user_settings()
            {
                "AllowExternalAccess": true
            }
        """
        return self.execute(
            "Get-CsTenantFederationConfiguration | ConvertTo-Json -Depth 10",
            json_parse=True,
        )

    def connect_exchange_online(self) -> dict:
        """
        Connect to Exchange Online PowerShell Module.

        Establishes a connection to Exchange Online using the initialized credentials.
        Supports two authentication methods:
        1. Application authentication (client_id/client_secret)
        2. Certificate authentication (certificate_content in base64/client_id)

        Returns:
            dict: Connection status information in JSON format.

        Note:
            This method requires the Exchange Online PowerShell module to be installed.
        """
        # Certificate Auth
        if self.execute("Write-Output $certificate") != "":
            return self.test_exchange_certificate_connection()
        # Application Auth
        return self.test_exchange_connection()

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
            "Get-AdminAuditLogConfig | Select-Object UnifiedAuditLogIngestionEnabled | ConvertTo-Json -Depth 10",
            json_parse=True,
        )

    def get_malware_filter_policy(self) -> dict:
        """
        Get Defender Malware Filter Policy.

        Retrieves the current Defender anti-malware filter policy settings.

        Returns:
            dict: Malware filter policy settings in JSON format.

        Example:
            >>> get_malware_filter_policy()
            {
                "EnableFileFilter": true,
                "Identity": "Default"
            }
        """
        return self.execute(
            "Get-MalwareFilterPolicy | ConvertTo-Json -Depth 10", json_parse=True
        )

    def get_malware_filter_rule(self) -> dict:
        """
        Get Defender Malware Filter Rule.

        Retrieves the current Defender anti-malware filter rule settings.

        Returns:
            dict: Malware filter rule settings in JSON format.

        Example:
            >>> get_malware_filter_rule()
            {
                "Name": "Default",
                "State": "Enabled"
            }
        """
        return self.execute(
            "Get-MalwareFilterRule | ConvertTo-Json -Depth 10", json_parse=True
        )

    def get_outbound_spam_filter_policy(self) -> dict:
        """
        Get Defender Outbound Spam Filter Policy.

        Retrieves the current Defender outbound spam filter policy settings.

        Returns:
            dict: Outbound spam filter policy settings in JSON format.

        Example:
            >>> get_outbound_spam_filter_policy()
            {
                "NotifyOutboundSpam": true,
                "BccSuspiciousOutboundMail": true,
                "BccSuspiciousOutboundAdditionalRecipients": [],
                "NotifyOutboundSpamRecipients": []
            }
        """
        return self.execute(
            "Get-HostedOutboundSpamFilterPolicy | ConvertTo-Json -Depth 10",
            json_parse=True,
        )

    def get_outbound_spam_filter_rule(self) -> dict:
        """
        Get Defender Outbound Spam Filter Rule.

        Retrieves the current Defender outbound spam filter rule settings.

        Returns:
            dict: Outbound spam filter rule settings in JSON format.

        Example:
            >>> get_outbound_spam_filter_rule()
            {
                "State": "Enabled"
            }
        """
        return self.execute(
            "Get-HostedOutboundSpamFilterRule | ConvertTo-Json -Depth 10",
            json_parse=True,
        )

    def get_antiphishing_policy(self) -> dict:
        """
        Get Defender Antiphishing Policy.

        Retrieves the current Defender anti-phishing policy settings.

        Returns:
            dict: Antiphishing policy settings in JSON format.

        Example:
            >>> get_antiphishing_policy()
            {
                "EnableSpoofIntelligence": true,
                "AuthenticationFailAction": "Quarantine",
                "DmarcRejectAction": "Quarantine",
                "DmarcQuarantineAction": "Quarantine",
                "EnableFirstContactSafetyTips": true,
                "EnableUnauthenticatedSender": true,
                "EnableViaTag": true,
                "HonorDmarcPolicy": true,
                "IsDefault": false
            }
        """
        return self.execute(
            "Get-AntiPhishPolicy | ConvertTo-Json -Depth 10", json_parse=True
        )

    def get_antiphishing_rules(self) -> dict:
        """
        Get Defender Antiphishing Rules.

        Retrieves the current Defender anti-phishing rules.

        Returns:
            dict: Antiphishing rules in JSON format.

        Example:
            >>> get_antiphishing_rules()
            {
                "Name": "Rule1",
                "State": Enabled,
            }
        """
        return self.execute(
            "Get-AntiPhishRule | ConvertTo-Json -Depth 10", json_parse=True
        )

    def get_organization_config(self) -> dict:
        """
        Get Exchange Online Organization Configuration.

        Retrieves the current Exchange Online organization configuration settings.

        Returns:
            dict: Organization configuration settings in JSON format.

        Example:
            >>> get_organization_config()
            {
                "Name": "MyOrganization",
                "Guid": "12345678-1234-1234-1234-123456789012"
                "AuditDisabled": false
            }
        """
        return self.execute(
            "Get-OrganizationConfig | ConvertTo-Json -Depth 10", json_parse=True
        )

    def get_mailbox_audit_config(self) -> dict:
        """
        Get Exchange Online Mailbox Audit Configuration.

        Retrieves the current mailbox audit configuration settings for Exchange Online.

        Returns:
            dict: Mailbox audit configuration settings in JSON format.

        Example:
            >>> get_mailbox_audit_config()
            {
                "Name": "MyMailbox",
                "Id": "12345678-1234-1234-1234-123456789012",
                "AuditBypassEnabled": false
            }
        """
        return self.execute(
            "Get-MailboxAuditBypassAssociation | ConvertTo-Json -Depth 10",
            json_parse=True,
        )

    def get_mailbox_policy(self) -> dict:
        """
        Get Mailbox Policy.

        Retrieves the current mailbox policy settings for Exchange Online.

        Returns:
            dict: Mailbox policy settings in JSON format.

        Example:
            >>> get_mailbox_policy()
            {
                "Id": "OwaMailboxPolicy-Default",
                "AdditionalStorageProvidersAvailable": True
            }
        """
        return self.execute(
            "Get-OwaMailboxPolicy | ConvertTo-Json -Depth 10", json_parse=True
        )

    def get_external_mail_config(self) -> dict:
        """
        Get Exchange Online External Mail Configuration.

        Retrieves the current external mail configuration settings for Exchange Online.

        Returns:
            dict: External mail configuration settings in JSON format.

        Example:
            >>> get_external_mail_config()
            {
                "Identity": "MyExternalMail",
                "ExternalMailTagEnabled": true
            }
        """
        return self.execute(
            "Get-ExternalInOutlook | ConvertTo-Json -Depth 10", json_parse=True
        )

    def get_transport_rules(self) -> dict:
        """
        Get Exchange Online Transport Rules.

        Retrieves the current transport rules configured in Exchange Online.

        Returns:
            dict: Transport rules in JSON format.

        Example:
            >>> get_transport_rules()
            {
                "Name": "Rule1",
                "SetSCL": -1,
                "SenderDomainIs": ["example.com"]
            }
        """
        return self.execute(
            "Get-TransportRule | ConvertTo-Json -Depth 10", json_parse=True
        )

    def get_connection_filter_policy(self) -> dict:
        """
        Get Exchange Online Connection Filter Policy.

        Retrieves the current connection filter policy settings for Exchange Online.

        Returns:
            dict: Connection filter policy settings in JSON format.

        Example:
            >>> get_connection_filter_policy()
            {
                "Identity": "Default",
                "IPAllowList": []"
            }
        """
        return self.execute(
            "Get-HostedConnectionFilterPolicy -Identity Default | ConvertTo-Json -Depth 10",
            json_parse=True,
        )

    def get_dkim_config(self) -> dict:
        """
        Get DKIM Signing Configuration.

        Retrieves the current DKIM signing configuration settings for Exchange Online.

        Returns:
            dict: DKIM signing configuration settings in JSON format.

        Example:
            >>> get_dkim_config()
            {
                "Id": "12345678-1234-1234-1234-123456789012",
                "Enabled": true
            }
        """
        return self.execute(
            "Get-DkimSigningConfig | ConvertTo-Json -Depth 10", json_parse=True
        )

    def get_inbound_spam_filter_policy(self) -> dict:
        """
        Get Inbound Spam Filter Policy.

        Retrieves the current inbound spam filter policy settings for Exchange Online.

        Returns:
            dict: Inbound spam filter policy settings in JSON format.

        Example:
            >>> get_inbound_spam_filter_policy()
            {
                "Identity": "Default",
                "AllowedSenderDomains": "[]"
            }
        """
        return self.execute(
            "Get-HostedContentFilterPolicy | ConvertTo-Json -Depth 10",
            json_parse=True,
        )

    def get_inbound_spam_filter_rule(self) -> dict:
        """
        Get Inbound Spam Filter Rule.

        Retrieves the current inbound spam filter rule settings for Exchange Online.

        Returns:
            dict: Inbound spam filter rule settings in JSON format.

        Example:
            >>> get_inbound_spam_filter_rule()
            {
                "Name": "Rule1",
                "State": "Enabled"
            }
        """
        return self.execute(
            "Get-HostedContentFilterRule | ConvertTo-Json -Depth 10",
            json_parse=True,
        )

    def get_report_submission_policy(self) -> dict:
        """
        Get Exchange Online Report Submission Policy.

        Retrieves the current Exchange Online report submission policy settings.

        Returns:
            dict: Report submission policy settings in JSON format.

        Example:
            >>> get_report_submission_policy()
            {
                "Id": "DefaultReportSubmissionPolicy",
                "Identity": "DefaultReportSubmissionPolicy",
                "Name": "DefaultReportSubmissionPolicy",
                "ReportChatMessageEnabled": true,
                "ReportChatMessageToCustomizedAddressEnabled": true,
                "ReportJunkAddresses": [],
                "ReportJunkToCustomizedAddress": true,
                "ReportNotJunkAddresses": [],
                "ReportNotJunkToCustomizedAddress": true,
                "ReportPhishAddresses": [],
                "ReportPhishToCustomizedAddress": true,
                "ThirdPartyReportAddresses": [],
                ...
            }
        """
        return self.execute(
            "Get-ReportSubmissionPolicy | ConvertTo-Json -Depth 10",
            json_parse=True,
        )

    def get_role_assignment_policies(self) -> dict:
        """
        Get Role Assignment Policies.

        Retrieves the current role assignment policies for Exchange Online.

        Returns:
            dict: Role assignment policies in JSON format.

        Example:
            >>> get_role_assignment_policies()
            {
                "Name": "Default Role Assignment Policy",
                "Guid": "12345678-1234-1234-1234-123456789012",
                "AssignedRoles": ["MyRole"]
            }
        """
        return self.execute(
            "Get-RoleAssignmentPolicy | ConvertTo-Json -Depth 10",
            json_parse=True,
        )

    def get_mailbox_audit_properties(self) -> dict:
        """
        Get Mailbox Properties.

        Retrieves the properties of all mailboxes in the organization in Exchange Online.

        Args:
            mailbox (str): The email address or identifier of the mailbox.

        Returns:
            dict: Mailbox properties in JSON format.

        Example:
            >>> get_mailbox_properties()
            {
                "UserPrincipalName": "User1",
                "AuditEnabled": "false"
                "AuditAdmin": [
                    "Update",
                    "MoveToDeletedItems",
                    "SoftDelete",
                    "HardDelete",
                    "SendAs",
                    "SendOnBehalf",
                    "Create",
                    "UpdateFolderPermissions",
                    "UpdateInboxRules",
                    "UpdateCalendarDelegation",
                    "ApplyRecord",
                    "MailItemsAccessed",
                    "Send"
                ],
                "AuditDelegate": [
                    "Update",
                    "MoveToDeletedItems",
                    "SoftDelete",
                    "HardDelete",
                    "SendAs",
                    "SendOnBehalf",
                    "Create",
                    "UpdateFolderPermissions",
                    "UpdateInboxRules",
                    "ApplyRecord",
                    "MailItemsAccessed"
                ],
                "AuditOwner": [
                    "Update",
                    "MoveToDeletedItems",
                    "SoftDelete",
                    "HardDelete",
                    "UpdateFolderPermissions",
                    "UpdateInboxRules",
                    "UpdateCalendarDelegation",
                    "ApplyRecord",
                    "MailItemsAccessed",
                    "Send"
                ],
                "AuditLogAgeLimit": "90",
                "Identity": "User1",
            }
        """
        return self.execute(
            "Get-EXOMailbox -PropertySets Audit -ResultSize Unlimited | ConvertTo-Json -Depth 10",
            json_parse=True,
        )

    def get_transport_config(self) -> dict:
        """
        Get Exchange Online Transport Configuration.

        Retrieves the current transport configuration settings for Exchange Online.

        Returns:
            dict: Transport configuration settings in JSON format.

        Example:
            >>> get_transport_config()
            {
                "SmtpClientAuthenticationDisabled": True,
            }
        """
        return self.execute(
            "Get-TransportConfig | ConvertTo-Json -Depth 10", json_parse=True
        )

    def get_sharing_policy(self) -> dict:
        """
        Get Exchange Online Sharing Policy.

        Retrieves the current sharing policy settings for Exchange Online.

        Returns:
            dict: Sharing policy settings in JSON format.

        Example:
            >>> get_sharing_policy()
            {
                "Identity": "Default",
                "Enabled": true
            }
        """
        return self.execute(
            "Get-SharingPolicy | ConvertTo-Json -Depth 10", json_parse=True
        )

    def get_teams_protection_policy(self) -> dict:
        """
        Get Teams Protection Policy.

        Retrieves the Teams protection policy settings including Zero-hour auto purge (ZAP) configuration.

        Returns:
            dict: Teams protection policy settings in JSON format.

        Example:
            >>> get_teams_protection_policy()
            {
                "Identity": "Teams Protection Policy",
                "ZapEnabled": True
            }
        """
        return self.execute(
            "Get-TeamsProtectionPolicy | ConvertTo-Json -Depth 10", json_parse=True
        )

    def get_shared_mailboxes(self) -> dict:
        """
        Get Exchange Online Shared Mailboxes.

        Retrieves all shared mailboxes from Exchange Online with their external
        directory object IDs for cross-referencing with Entra ID user accounts.

        Returns:
            dict: Shared mailbox information in JSON format.

        Example:
            >>> get_shared_mailboxes()
            [
                {
                    "DisplayName": "Support Mailbox",
                    "UserPrincipalName": "support@contoso.com",
                    "ExternalDirectoryObjectId": "12345678-1234-1234-1234-123456789012",
                    "Identity": "support@contoso.com"
                }
            ]
        """
        return self.execute(
            "Get-EXOMailbox -RecipientTypeDetails SharedMailbox -ResultSize Unlimited | Select-Object DisplayName, UserPrincipalName, ExternalDirectoryObjectId, Identity | ConvertTo-Json -Depth 10",
            json_parse=True,
        )

    def get_user_account_status(self) -> dict:
        """
        Get User Account Status.

        Retrieves the current user account status settings for Exchange Online.

        Returns:
            dict: User account status settings in JSON format.
        """
        return self.execute(
            "$dict=@{}; Get-User -ResultSize Unlimited | ForEach-Object { $dict[$_.ExternalDirectoryObjectId] = @{ AccountDisabled = $_.AccountDisabled } }; $dict | ConvertTo-Json -Depth 10",
            json_parse=True,
        )


# This function is used to install the required M365 PowerShell modules in Docker containers
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
        "MSAL.PS",
    ]

    pwsh = PowerShellSession()
    try:
        for module in REQUIRED_MODULES:
            try:
                # Check if module is already installed
                result = pwsh.execute(f"Get-Module -ListAvailable {module}", timeout=5)

                # Install module if not installed
                if not result:
                    install_result = pwsh.execute(
                        f"Install-Module {module} -Force -AllowClobber -Scope CurrentUser",
                        timeout=60,
                    )
                    if install_result:
                        logger.warning(
                            f"Unexpected output while installing module {module}: {install_result}"
                        )
                    else:
                        logger.info(f"Successfully installed module {module}")

                    # Import module
                    pwsh.execute(f'Import-Module "{module}" -Force', timeout=1)

            except Exception as error:
                logger.error(f"Failed to initialize module {module}: {str(error)}")
                return False

        return True
    finally:
        pwsh.close()


def main():
    if initialize_m365_powershell_modules():
        logger.info("M365 PowerShell modules initialized successfully")
    else:
        logger.error("Failed to initialize M365 PowerShell modules")


if __name__ == "__main__":
    main()
