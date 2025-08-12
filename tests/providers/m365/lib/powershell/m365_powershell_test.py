import base64
from unittest.mock import MagicMock, call, patch

import pytest

from prowler.lib.powershell.powershell import PowerShellSession
from prowler.providers.m365.exceptions.exceptions import (
    M365CertificateCreationError,
    M365GraphConnectionError,
    M365UserCredentialsError,
    M365UserNotBelongingToTenantError,
)
from prowler.providers.m365.lib.powershell.m365_powershell import M365PowerShell
from prowler.providers.m365.models import M365Credentials, M365IdentityInfo


class Testm365PowerShell:
    @patch("subprocess.Popen")
    def test_init(self, mock_popen):
        mock_process = MagicMock()
        mock_popen.return_value = mock_process
        credentials = M365Credentials(user="test@example.com", passwd="test_password")
        identity = M365IdentityInfo(
            identity_id="test_id",
            identity_type="User",
            tenant_id="test_tenant",
            tenant_domain="example.com",
            tenant_domains=["example.com"],
            location="test_location",
        )

        with patch.object(M365PowerShell, "init_credential") as mock_init_credential:
            session = M365PowerShell(credentials, identity)

            mock_popen.assert_called_once()
            mock_init_credential.assert_called_once_with(credentials)
            assert session.process == mock_process
            assert session.END == "<END>"
            session.close()

    @patch("subprocess.Popen")
    def test_sanitize(self, _):
        credentials = M365Credentials(user="test@example.com", passwd="test_password")
        identity = M365IdentityInfo(
            identity_id="test_id",
            identity_type="User",
            tenant_id="test_tenant",
            tenant_domain="example.com",
            tenant_domains=["example.com"],
            location="test_location",
        )
        session = M365PowerShell(credentials, identity)

        test_cases = [
            ("test@example.com", "test@example.com"),
            ("test@example.com!", "test@example.com"),
            ("test@example.com#", "test@example.com"),
            ("test@example.com$", "test@example.com"),
            ("test@example.com%", "test@example.com"),
            ("test@example.com^", "test@example.com"),
            ("test@example.com&", "test@example.com"),
            ("test@example.com*", "test@example.com"),
            ("test@example.com(", "test@example.com"),
            ("test@example.com)", "test@example.com"),
            ("test@example.com-", "test@example.com-"),
            ("test@example.com_", "test@example.com_"),
            ("test@example.com+", "test@example.com+"),
            ("test_;echo pwned;password", "test_echopwnedpassword"),
        ]

        for input_str, expected in test_cases:
            assert session.sanitize(input_str) == expected
        session.close()

    @patch("subprocess.Popen")
    def test_init_credential(self, mock_popen):
        mock_process = MagicMock()
        mock_popen.return_value = mock_process
        credentials = M365Credentials(
            user="test@example.com",
            passwd="test_password",
            encrypted_passwd="test_password",
            client_id="test_client_id",
            client_secret="test_client_secret",
            tenant_id="test_tenant_id",
        )
        identity = M365IdentityInfo(
            identity_id="test_id",
            identity_type="User",
            tenant_id="test_tenant",
            tenant_domain="example.com",
            tenant_domains=["example.com"],
            location="test_location",
        )
        session = M365PowerShell(credentials, identity)

        # Mock encrypt_password to return a known value
        session.encrypt_password = MagicMock(return_value="encrypted_password")
        session.execute = MagicMock()

        session.init_credential(credentials)

        # Verify encrypt_password was called
        session.encrypt_password.assert_any_call(credentials.passwd)

        # Verify execute was called with the correct commands
        session.execute.assert_any_call(f'$user = "{credentials.user}"')
        session.execute.assert_any_call(
            f'$secureString = "{credentials.encrypted_passwd}" | ConvertTo-SecureString'
        )
        session.execute.assert_any_call(
            "$credential = New-Object System.Management.Automation.PSCredential ($user, $secureString)"
        )
        session.close()

    @patch("subprocess.Popen")
    def test_test_credentials_exchange_success(self, mock_popen):
        mock_process = MagicMock()
        mock_popen.return_value = mock_process

        credentials = M365Credentials(
            user="test@contoso.onmicrosoft.com",
            passwd="test_password",
            encrypted_passwd="test_encrypted_password",
            client_id="test_client_id",
            client_secret="test_client_secret",
            tenant_id="test_tenant_id",
        )
        identity = M365IdentityInfo(
            identity_id="test_id",
            identity_type="User",
            tenant_id="test_tenant",
            tenant_domain="contoso.onmicrosoft.com",
            tenant_domains=["contoso.onmicrosoft.com"],
            location="test_location",
            user="test@contoso.onmicrosoft.com",
        )
        session = M365PowerShell(credentials, identity)

        # Mock encrypt_password to return a known value
        session.encrypt_password = MagicMock(return_value="encrypted_password")

        # Mock execute to simulate successful Exchange connection
        def mock_execute_side_effect(command):
            if "Connect-ExchangeOnline" in command:
                return "Connected successfully https://aka.ms/exov3-module"
            return ""

        session.execute = MagicMock(side_effect=mock_execute_side_effect)

        # Execute the test
        result = session.test_credentials(credentials)
        assert result is True

        # Verify execute was called with the correct commands
        session.execute.assert_any_call(
            f'$securePassword = "{credentials.encrypted_passwd}" | ConvertTo-SecureString'
        )
        session.execute.assert_any_call(
            f'$credential = New-Object System.Management.Automation.PSCredential("{session.sanitize(credentials.user)}", $securePassword)'
        )
        # Exchange connection should be tested
        session.execute.assert_any_call(
            "Connect-ExchangeOnline -Credential $credential"
        )

        # Verify Teams connection was NOT called (since Exchange succeeded)
        teams_calls = [
            call
            for call in session.execute.call_args_list
            if "Connect-MicrosoftTeams" in str(call)
        ]
        assert (
            len(teams_calls) == 0
        ), "Teams connection should not be called when Exchange succeeds"

        session.close()

    @patch("subprocess.Popen")
    def test_test_credentials_exchange_fail_teams_success(self, mock_popen):
        mock_process = MagicMock()
        mock_popen.return_value = mock_process

        credentials = M365Credentials(
            user="test@contoso.onmicrosoft.com",
            passwd="test_password",
            encrypted_passwd="test_encrypted_password",
            client_id="test_client_id",
            client_secret="test_client_secret",
            tenant_id="test_tenant_id",
        )
        identity = M365IdentityInfo(
            identity_id="test_id",
            identity_type="User",
            tenant_id="test_tenant",
            tenant_domain="contoso.onmicrosoft.com",
            tenant_domains=["contoso.onmicrosoft.com"],
            location="test_location",
            user="test@contoso.onmicrosoft.com",
        )
        session = M365PowerShell(credentials, identity)

        # Mock encrypt_password to return a known value
        session.encrypt_password = MagicMock(return_value="encrypted_password")

        # Mock execute to simulate Exchange fail and Teams success
        def mock_execute_side_effect(command):
            if "Connect-ExchangeOnline" in command:
                return (
                    "Connection failed"  # No "https://aka.ms/exov3-module" in response
                )
            elif "Connect-MicrosoftTeams" in command:
                return "Connected successfully test@contoso.onmicrosoft.com"
            return ""

        session.execute = MagicMock(side_effect=mock_execute_side_effect)

        # Execute the test
        result = session.test_credentials(credentials)
        assert result is True

        # Verify execute was called with the correct commands
        session.execute.assert_any_call(
            f'$securePassword = "{credentials.encrypted_passwd}" | ConvertTo-SecureString'
        )
        session.execute.assert_any_call(
            f'$credential = New-Object System.Management.Automation.PSCredential("{session.sanitize(credentials.user)}", $securePassword)'
        )
        # Both Exchange and Teams connections should be tested
        session.execute.assert_any_call(
            "Connect-ExchangeOnline -Credential $credential"
        )
        session.execute.assert_any_call(
            "Connect-MicrosoftTeams -Credential $credential"
        )

        session.close()

    @patch("subprocess.Popen")
    def test_test_credentials_application_auth(self, mock_popen):
        mock_process = MagicMock()
        mock_popen.return_value = mock_process
        credentials = M365Credentials(
            user="",
            passwd="",
            encrypted_passwd="",
            client_id="test_client_id",
            client_secret="test_client_secret",
            tenant_id="test_tenant_id",
        )
        identity = M365IdentityInfo(
            identity_id="test_id",
            identity_type="Application",
            tenant_id="test_tenant",
            tenant_domain="contoso.onmicrosoft.com",
            tenant_domains=["contoso.onmicrosoft.com"],
            location="test_location",
        )
        session = M365PowerShell(credentials, identity)
        session.execute = MagicMock(return_value="sometoken")

        result = session.test_credentials(credentials)
        assert result is True
        session.execute.assert_any_call("Write-Output $graphToken")
        session.close()

    @patch("subprocess.Popen")
    @patch("msal.ConfidentialClientApplication")
    def test_test_credentials_user_not_belonging_to_tenant(self, mock_msal, mock_popen):
        mock_process = MagicMock()
        mock_popen.return_value = mock_process
        mock_msal_instance = MagicMock()
        mock_msal.return_value = mock_msal_instance
        mock_msal_instance.acquire_token_by_username_password.return_value = {
            "access_token": "test_token"
        }

        credentials = M365Credentials(
            user="user@otherdomain.com",
            passwd="test_password",
            client_id="test_client_id",
            client_secret="test_client_secret",
            tenant_id="test_tenant_id",
        )
        identity = M365IdentityInfo(
            identity_id="test_id",
            identity_type="User",
            tenant_id="test_tenant",
            tenant_domain="contoso.onmicrosoft.com",
            tenant_domains=["contoso.onmicrosoft.com"],
            location="test_location",
        )
        session = M365PowerShell(credentials, identity)

        # Mock the execute method to return the decrypted password
        def mock_execute(command, *args, **kwargs):
            if "Write-Output" in command:
                return "decrypted_password"
            return None

        session.execute = MagicMock(side_effect=mock_execute)
        session.process.stdin.write = MagicMock()
        session.read_output = MagicMock(return_value="decrypted_password")

        with pytest.raises(M365UserNotBelongingToTenantError) as exception:
            session.test_credentials(credentials)

        assert exception.type == M365UserNotBelongingToTenantError
        assert (
            "The user domain otherdomain.com does not match any of the tenant domains: contoso.onmicrosoft.com"
            in str(exception.value)
        )

        # Verify MSAL was not called since domain validation failed first
        mock_msal.assert_not_called()
        mock_msal_instance.acquire_token_by_username_password.assert_not_called()

        session.close()

    @patch("subprocess.Popen")
    def test_test_credentials_auth_failure_aadsts_error(self, mock_popen):
        mock_process = MagicMock()
        mock_popen.return_value = mock_process

        credentials = M365Credentials(
            user="test@contoso.onmicrosoft.com",
            passwd="test_password",
            encrypted_passwd="test_encrypted_password",
            client_id="test_client_id",
            client_secret="test_client_secret",
            tenant_id="test_tenant_id",
        )
        identity = M365IdentityInfo(
            identity_id="test_id",
            identity_type="User",
            tenant_id="test_tenant",
            tenant_domain="contoso.onmicrosoft.com",
            tenant_domains=["contoso.onmicrosoft.com"],
            location="test_location",
        )
        session = M365PowerShell(credentials, identity)

        # Mock encrypt_password and execute to simulate AADSTS error
        session.encrypt_password = MagicMock(return_value="encrypted_password")
        session.execute = MagicMock(
            return_value="AADSTS50126: Error validating credentials due to invalid username or password"
        )

        with pytest.raises(M365UserCredentialsError) as exc_info:
            session.test_credentials(credentials)

        assert (
            "AADSTS50126: Error validating credentials due to invalid username or password"
            in str(exc_info.value)
        )

        # Verify execute was called with the correct commands
        session.execute.assert_any_call(
            f'$securePassword = "{credentials.encrypted_passwd}" | ConvertTo-SecureString'
        )
        session.execute.assert_any_call(
            f'$credential = New-Object System.Management.Automation.PSCredential("{session.sanitize(credentials.user)}", $securePassword)'
        )
        session.execute.assert_any_call(
            "Connect-ExchangeOnline -Credential $credential"
        )

        session.close()

    @patch("subprocess.Popen")
    def test_test_credentials_auth_failure_no_access_token(self, mock_popen):
        mock_process = MagicMock()
        mock_popen.return_value = mock_process

        credentials = M365Credentials(
            user="test@contoso.onmicrosoft.com",
            passwd="test_password",
            encrypted_passwd="test_encrypted_password",
            client_id="test_client_id",
            client_secret="test_client_secret",
            tenant_id="test_tenant_id",
        )
        identity = M365IdentityInfo(
            identity_id="test_id",
            identity_type="User",
            tenant_id="test_tenant",
            tenant_domain="contoso.onmicrosoft.com",
            tenant_domains=["contoso.onmicrosoft.com"],
            location="test_location",
        )
        session = M365PowerShell(credentials, identity)

        # Mock encrypt_password and execute to simulate AADSTS invalid grant error
        session.encrypt_password = MagicMock(return_value="encrypted_password")
        session.execute = MagicMock(
            return_value="AADSTS70002: The request body must contain the following parameter: 'client_secret' or 'client_assertion'."
        )

        with pytest.raises(M365UserCredentialsError) as exc_info:
            session.test_credentials(credentials)

        assert (
            "AADSTS70002: The request body must contain the following parameter: 'client_secret' or 'client_assertion'."
            in str(exc_info.value)
        )

        # Verify execute was called with the correct commands
        session.execute.assert_any_call(
            f'$securePassword = "{credentials.encrypted_passwd}" | ConvertTo-SecureString'
        )
        session.execute.assert_any_call(
            f'$credential = New-Object System.Management.Automation.PSCredential("{session.sanitize(credentials.user)}", $securePassword)'
        )
        session.execute.assert_any_call(
            "Connect-ExchangeOnline -Credential $credential"
        )

        session.close()

    @patch("subprocess.Popen")
    def test_remove_ansi(self, mock_popen):
        credentials = M365Credentials(user="test@example.com", passwd="test_password")
        identity = M365IdentityInfo(
            identity_id="test_id",
            identity_type="User",
            tenant_id="test_tenant",
            tenant_domain="example.com",
            tenant_domains=["example.com"],
            location="test_location",
        )
        session = M365PowerShell(credentials, identity)

        test_cases = [
            ("\x1b[32mSuccess\x1b[0m", "Success"),
            ("\x1b[31mError\x1b[0m", "Error"),
            ("\x1b[33mWarning\x1b[0m", "Warning"),
            ("Normal text", "Normal text"),
            ("\x1b[1mBold\x1b[0m", "Bold"),
        ]

        for input_str, expected in test_cases:
            assert session.remove_ansi(input_str) == expected
        session.close()

    @patch("subprocess.Popen")
    def test_execute(self, mock_popen):
        mock_process = MagicMock()
        mock_popen.return_value = mock_process
        credentials = M365Credentials(user="test@example.com", passwd="test_password")
        identity = M365IdentityInfo(
            identity_id="test_id",
            identity_type="User",
            tenant_id="test_tenant",
            tenant_domain="example.com",
            tenant_domains=["example.com"],
            location="test_location",
        )
        session = M365PowerShell(credentials, identity)
        command = "Get-Command"
        expected_output = {"Name": "Get-Command"}

        with patch.object(session, "execute", return_value=expected_output):
            result = session.execute(command)
            assert result == expected_output
        session.close()

    @patch("subprocess.Popen")
    def test_read_output(self, mock_popen):
        """Test the read_output method with various scenarios"""
        mock_process = MagicMock()
        mock_popen.return_value = mock_process
        credentials = M365Credentials(user="test@example.com", passwd="test_password")
        identity = M365IdentityInfo(
            identity_id="test_id",
            identity_type="User",
            tenant_id="test_tenant",
            tenant_domain="example.com",
            tenant_domains=["example.com"],
            location="test_location",
        )
        session = M365PowerShell(credentials, identity)

        # Test 1: Normal stdout output
        mock_process.stdout.readline.side_effect = [
            "test@example.com\n",
            f"{session.END}\n",
        ]
        mock_process.stderr.readline.return_value = f"Write-Error: {session.END}\n"
        with patch.object(session, "remove_ansi", side_effect=lambda x: x):
            result = session.read_output()
            assert result == "test@example.com"

        # Test 2: Error in stderr
        mock_process.stdout.readline.side_effect = ["\n", f"{session.END}\n"]
        mock_process.stderr.readline.side_effect = [
            "Write-Error: Authentication failed\n",
            f"Write-Error: {session.END}\n",
        ]
        with patch.object(session, "remove_ansi", side_effect=lambda x: x):
            with patch("prowler.lib.logger.logger.error") as mock_error:
                result = session.read_output()
                assert result == ""
                mock_error.assert_called_once_with(
                    "PowerShell error output: Write-Error: Authentication failed"
                )

        # Test 3: Timeout in stdout
        mock_process.stdout.readline.side_effect = ["test output\n"]  # No END marker
        mock_process.stderr.readline.return_value = f"Write-Error: {session.END}\n"
        result = session.read_output(timeout=0.1, default="timeout")
        assert result == "timeout"

        session.close()

    @patch("subprocess.Popen")
    def test_json_parse_output(self, mock_popen):
        mock_process = MagicMock()
        mock_popen.return_value = mock_process
        credentials = M365Credentials(user="test@example.com", passwd="test_password")
        identity = M365IdentityInfo(
            identity_id="test_id",
            identity_type="User",
            tenant_id="test_tenant",
            tenant_domain="example.com",
            tenant_domains=["example.com"],
            location="test_location",
        )
        session = M365PowerShell(credentials, identity)

        test_cases = [
            ('{"key": "value"}', {"key": "value"}),
            ('[{"key": "value"}]', [{"key": "value"}]),
            (
                '[{"key": "value"},{"key": "value"}]',
                [{"key": "value"}, {"key": "value"}],
            ),
            ("[{}]", [{}]),
            ("[{},{}]", [{}, {}]),
            ("not json", {}),
            ("", {}),
        ]

        for input_str, expected in test_cases:
            result = session.json_parse_output(input_str)
            assert result == expected
        session.close()

    @patch("subprocess.Popen")
    def test_close(self, mock_popen):
        mock_process = MagicMock()
        mock_popen.return_value = mock_process
        credentials = M365Credentials(user="test@example.com", passwd="test_password")
        identity = M365IdentityInfo(
            identity_id="test_id",
            identity_type="User",
            tenant_id="test_tenant",
            tenant_domain="example.com",
            tenant_domains=["example.com"],
            location="test_location",
        )
        session = M365PowerShell(credentials, identity)

        session.close()

        mock_process.stdin.flush.assert_called_once()
        mock_process.terminate.assert_called_once()

    @patch("subprocess.Popen")
    def test_initialize_m365_powershell_modules_success(self, mock_popen):
        """Test initialize_m365_powershell_modules when all modules are successfully initialized"""
        mock_process = MagicMock()
        mock_popen.return_value = mock_process

        # Mock the execute method to simulate successful module installation
        def mock_execute(command, *args, **kwargs):
            if "Get-Module" in command:
                return None  # Module not installed
            elif "Install-Module" in command:
                return None  # Installation successful
            elif "Import-Module" in command:
                return None  # Import successful
            return None

        with (
            patch.object(
                PowerShellSession, "execute", side_effect=mock_execute
            ) as mock_execute_obj,
            patch("prowler.lib.logger.logger.info") as mock_info,
        ):
            from prowler.providers.m365.lib.powershell.m365_powershell import (
                initialize_m365_powershell_modules,
            )

            result = initialize_m365_powershell_modules()

            # Verify successful initialization
            assert result is True
            # Verify that execute was called for each module
            assert mock_execute_obj.call_count == 9  # 3 modules * 3 commands each
            # Verify success messages were logged
            mock_info.assert_any_call(
                "Successfully installed module ExchangeOnlineManagement"
            )
            mock_info.assert_any_call("Successfully installed module MicrosoftTeams")
            mock_info.assert_any_call("Successfully installed module MSAL.PS")

    @patch("subprocess.Popen")
    def test_initialize_m365_powershell_modules_failure(self, mock_popen):
        """Test initialize_m365_powershell_modules when module initialization fails"""
        mock_process = MagicMock()
        mock_popen.return_value = mock_process

        # Mock the execute method to simulate installation failure
        def mock_execute(command, *args, **kwargs):
            if "Get-Module" in command:
                return None  # Module not installed
            elif "Install-Module" in command:
                raise Exception("Installation failed")
            return None

        with (
            patch.object(
                PowerShellSession, "execute", side_effect=mock_execute
            ) as mock_execute_obj,
            patch("prowler.lib.logger.logger.error") as mock_error,
        ):
            from prowler.providers.m365.lib.powershell.m365_powershell import (
                initialize_m365_powershell_modules,
            )

            result = initialize_m365_powershell_modules()

            # Verify failed initialization
            assert result is False
            # Verify that execute was called at least twice
            assert mock_execute_obj.call_count >= 2
            # Verify error was logged
            mock_error.assert_called_with(
                "Failed to initialize module ExchangeOnlineManagement: Installation failed"
            )

    @patch("subprocess.Popen")
    def test_main_success(self, mock_popen):
        """Test main() function when module initialization is successful"""
        mock_process = MagicMock()
        mock_popen.return_value = mock_process

        # Mock the execute method to simulate successful module installation
        def mock_execute(command, *args, **kwargs):
            if "Get-Module" in command:
                return None  # Module not installed
            elif "Install-Module" in command:
                return None  # Installation successful
            elif "Import-Module" in command:
                return None  # Import successful
            return None

        with (
            patch.object(PowerShellSession, "execute", side_effect=mock_execute),
            patch("prowler.lib.logger.logger.info") as mock_info,
            patch("prowler.lib.logger.logger.error") as mock_error,
        ):
            from prowler.providers.m365.lib.powershell.m365_powershell import main

            main()

            # Verify all info messages were logged in the correct order
            assert mock_info.call_count == 4
            mock_info.assert_has_calls(
                [
                    call("Successfully installed module ExchangeOnlineManagement"),
                    call("Successfully installed module MicrosoftTeams"),
                    call("Successfully installed module MSAL.PS"),
                    call("M365 PowerShell modules initialized successfully"),
                ]
            )
            # Verify no error was logged
            mock_error.assert_not_called()

    @patch("subprocess.Popen")
    def test_main_failure(self, mock_popen):
        """Test main() function when module initialization fails"""
        mock_process = MagicMock()
        mock_popen.return_value = mock_process

        # Mock the execute method to simulate installation failure
        def mock_execute(command, *args, **kwargs):
            if "Get-Module" in command:
                return None  # Module not installed
            elif "Install-Module" in command:
                raise Exception("Installation failed")
            return None

        with (
            patch.object(PowerShellSession, "execute", side_effect=mock_execute),
            patch("prowler.lib.logger.logger.info") as mock_info,
            patch("prowler.lib.logger.logger.error") as mock_error,
        ):
            from prowler.providers.m365.lib.powershell.m365_powershell import main

            main()

            # Verify all error messages were logged in the correct order
            assert mock_error.call_count == 2
            mock_error.assert_has_calls(
                [
                    call(
                        "Failed to initialize module ExchangeOnlineManagement: Installation failed"
                    ),
                    call("Failed to initialize M365 PowerShell modules"),
                ]
            )
            # Verify no info messages were logged
            mock_info.assert_not_called()

    @patch("subprocess.Popen")
    def test_test_graph_connection_success(self, mock_popen):
        """Test test_graph_connection when token is valid"""
        mock_process = MagicMock()
        mock_popen.return_value = mock_process
        credentials = M365Credentials(user="test@example.com", passwd="test_password")
        identity = M365IdentityInfo(
            identity_id="test_id",
            identity_type="Application",
            tenant_id="test_tenant",
            tenant_domain="example.com",
            tenant_domains=["example.com"],
            location="test_location",
        )
        session = M365PowerShell(credentials, identity)

        # Mock execute to return a valid token
        session.execute = MagicMock(return_value="valid_token")

        result = session.test_graph_connection()

        assert result is True
        session.execute.assert_called_once_with("Write-Output $graphToken")
        session.close()

    @patch("subprocess.Popen")
    def test_test_graph_connection_empty_token(self, mock_popen):
        """Test test_graph_connection when token is empty"""
        mock_process = MagicMock()
        mock_popen.return_value = mock_process
        credentials = M365Credentials(user="test@example.com", passwd="test_password")
        identity = M365IdentityInfo(
            identity_id="test_id",
            identity_type="Application",
            tenant_id="test_tenant",
            tenant_domain="example.com",
            tenant_domains=["example.com"],
            location="test_location",
        )
        session = M365PowerShell(credentials, identity)

        # Mock execute to return empty token
        session.execute = MagicMock(return_value="")

        with pytest.raises(M365GraphConnectionError) as exc_info:
            session.test_graph_connection()

        assert "Microsoft Graph token is empty or invalid" in str(exc_info.value)
        session.execute.assert_called_once_with("Write-Output $graphToken")
        session.close()

    @patch("subprocess.Popen")
    def test_test_graph_connection_exception(self, mock_popen):
        """Test test_graph_connection when an exception occurs"""
        mock_process = MagicMock()
        mock_popen.return_value = mock_process
        credentials = M365Credentials(user="test@example.com", passwd="test_password")
        identity = M365IdentityInfo(
            identity_id="test_id",
            identity_type="Application",
            tenant_id="test_tenant",
            tenant_domain="example.com",
            tenant_domains=["example.com"],
            location="test_location",
        )
        session = M365PowerShell(credentials, identity)

        # Mock execute to raise an exception
        session.execute = MagicMock(side_effect=Exception("PowerShell error"))

        with pytest.raises(M365GraphConnectionError) as exc_info:
            session.test_graph_connection()

        assert "Failed to connect to Microsoft Graph API: PowerShell error" in str(
            exc_info.value
        )
        session.close()

    @patch("subprocess.Popen")
    @patch("prowler.providers.m365.lib.powershell.m365_powershell.decode_jwt")
    def test_test_teams_connection_success(self, mock_decode_jwt, mock_popen):
        """Test test_teams_connection when token is valid"""
        mock_process = MagicMock()
        mock_popen.return_value = mock_process
        credentials = M365Credentials(user="test@example.com", passwd="test_password")
        identity = M365IdentityInfo(
            identity_id="test_id",
            identity_type="Application",
            tenant_id="test_tenant",
            tenant_domain="example.com",
            tenant_domains=["example.com"],
            location="test_location",
        )
        session = M365PowerShell(credentials, identity)

        # Mock execute to return valid responses
        def mock_execute(command, *args, **kwargs):
            if "Write-Output $teamsToken" in command:
                return "valid_teams_token"
            return None

        session.execute = MagicMock(side_effect=mock_execute)
        # Mock JWT decode to return proper permissions
        mock_decode_jwt.return_value = {"roles": ["application_access"]}

        result = session.test_teams_connection()

        assert result is True
        # Verify all expected PowerShell commands were called
        # 4 calls: teamstokenBody, teamsToken, Write-Output $teamsToken, Connect-MicrosoftTeams
        assert session.execute.call_count == 4
        mock_decode_jwt.assert_called_once_with("valid_teams_token")
        session.close()

    @patch("subprocess.Popen")
    @patch("prowler.providers.m365.lib.powershell.m365_powershell.decode_jwt")
    def test_test_teams_connection_missing_permissions(
        self, mock_decode_jwt, mock_popen
    ):
        """Test test_teams_connection when token lacks required permissions"""
        mock_process = MagicMock()
        mock_popen.return_value = mock_process
        credentials = M365Credentials(user="test@example.com", passwd="test_password")
        identity = M365IdentityInfo(
            identity_id="test_id",
            identity_type="Application",
            tenant_id="test_tenant",
            tenant_domain="example.com",
            tenant_domains=["example.com"],
            location="test_location",
        )
        session = M365PowerShell(credentials, identity)

        # Mock execute to return valid token but decode returns no permissions
        def mock_execute(command, *args, **kwargs):
            if "Write-Output $teamsToken" in command:
                return "valid_teams_token"
            return None

        session.execute = MagicMock(side_effect=mock_execute)
        # Mock JWT decode to return missing required permission
        mock_decode_jwt.return_value = {"roles": ["other_permission"]}

        with patch("prowler.lib.logger.logger.error") as mock_error:
            result = session.test_teams_connection()

        assert result is False
        mock_error.assert_called_once_with(
            "Microsoft Teams connection failed: Please check your permissions and try again."
        )
        session.close()

    @patch("subprocess.Popen")
    def test_test_teams_connection_exception(self, mock_popen):
        """Test test_teams_connection when an exception occurs"""
        mock_process = MagicMock()
        mock_popen.return_value = mock_process
        credentials = M365Credentials(user="test@example.com", passwd="test_password")
        identity = M365IdentityInfo(
            identity_id="test_id",
            identity_type="Application",
            tenant_id="test_tenant",
            tenant_domain="example.com",
            tenant_domains=["example.com"],
            location="test_location",
        )
        session = M365PowerShell(credentials, identity)

        # Mock execute to raise an exception
        session.execute = MagicMock(side_effect=Exception("Teams API error"))

        with patch("prowler.lib.logger.logger.error") as mock_error:
            result = session.test_teams_connection()

        assert result is False
        mock_error.assert_called_once_with(
            "Microsoft Teams connection failed: Teams API error. Please check your permissions and try again."
        )
        session.close()

    @patch("subprocess.Popen")
    @patch("prowler.providers.m365.lib.powershell.m365_powershell.decode_msal_token")
    def test_test_exchange_connection_success(self, mock_decode_msal_token, mock_popen):
        """Test test_exchange_connection when token is valid"""
        mock_process = MagicMock()
        mock_popen.return_value = mock_process
        credentials = M365Credentials(user="test@example.com", passwd="test_password")
        identity = M365IdentityInfo(
            identity_id="test_id",
            identity_type="Application",
            tenant_id="test_tenant",
            tenant_domain="example.com",
            tenant_domains=["example.com"],
            location="test_location",
        )
        session = M365PowerShell(credentials, identity)

        # Mock execute to return valid responses
        def mock_execute(command, *args, **kwargs):
            if "Write-Output $exchangeToken" in command:
                return "valid_exchange_token"
            return None

        session.execute = MagicMock(side_effect=mock_execute)
        # Mock MSAL token decode to return proper permissions
        mock_decode_msal_token.return_value = {"roles": ["Exchange.ManageAsApp"]}

        result = session.test_exchange_connection()

        assert result is True
        # Verify all expected PowerShell commands were called
        # 4 calls: SecureSecret, exchangeToken, Write-Output $exchangeToken, Connect-ExchangeOnline
        assert session.execute.call_count == 4
        mock_decode_msal_token.assert_called_once_with("valid_exchange_token")
        session.close()

    @patch("subprocess.Popen")
    @patch("prowler.providers.m365.lib.powershell.m365_powershell.decode_msal_token")
    def test_test_exchange_connection_missing_permissions(
        self, mock_decode_msal_token, mock_popen
    ):
        """Test test_exchange_connection when token lacks required permissions"""
        mock_process = MagicMock()
        mock_popen.return_value = mock_process
        credentials = M365Credentials(user="test@example.com", passwd="test_password")
        identity = M365IdentityInfo(
            identity_id="test_id",
            identity_type="Application",
            tenant_id="test_tenant",
            tenant_domain="example.com",
            tenant_domains=["example.com"],
            location="test_location",
        )
        session = M365PowerShell(credentials, identity)

        # Mock execute to return valid token but decode returns no permissions
        def mock_execute(command, *args, **kwargs):
            if "Write-Output $exchangeToken" in command:
                return "valid_exchange_token"
            return None

        session.execute = MagicMock(side_effect=mock_execute)
        # Mock MSAL token decode to return missing required permission
        mock_decode_msal_token.return_value = {"roles": ["other_permission"]}

        with patch("prowler.lib.logger.logger.error") as mock_error:
            result = session.test_exchange_connection()

        assert result is False
        mock_error.assert_called_once_with(
            "Exchange Online connection failed: Please check your permissions and try again."
        )
        session.close()

    @patch("subprocess.Popen")
    def test_test_exchange_connection_exception(self, mock_popen):
        """Test test_exchange_connection when an exception occurs"""
        mock_process = MagicMock()
        mock_popen.return_value = mock_process
        credentials = M365Credentials(user="test@example.com", passwd="test_password")
        identity = M365IdentityInfo(
            identity_id="test_id",
            identity_type="Application",
            tenant_id="test_tenant",
            tenant_domain="example.com",
            tenant_domains=["example.com"],
            location="test_location",
        )
        session = M365PowerShell(credentials, identity)

        # Mock execute to raise an exception
        session.execute = MagicMock(side_effect=Exception("Exchange API error"))

        with patch("prowler.lib.logger.logger.error") as mock_error:
            result = session.test_exchange_connection()

        assert result is False
        mock_error.assert_called_once_with(
            "Exchange Online connection failed: Exchange API error. Please check your permissions and try again."
        )
        session.close()

    @patch("subprocess.Popen")
    def test_encrypt_password(self, mock_popen):
        credentials = M365Credentials(user="test@example.com", passwd="test_password")
        identity = M365IdentityInfo(
            identity_id="test_id",
            identity_type="User",
            tenant_id="test_tenant",
            tenant_domain="example.com",
            tenant_domains=["example.com"],
            location="test_location",
        )
        session = M365PowerShell(credentials, identity)

        # Test non-Windows system (should use utf-16le hex encoding)
        from unittest import mock

        with mock.patch("platform.system", return_value="Linux"):
            result = session.encrypt_password("password123")
            expected = "password123".encode("utf-16le").hex()
            assert result == expected

        # Test Windows system with tuple return
        with mock.patch("platform.system", return_value="Windows"):
            import sys

            win32crypt_mock = mock.MagicMock()
            win32crypt_mock.CryptProtectData.return_value = (None, b"encrypted_bytes")
            sys.modules["win32crypt"] = win32crypt_mock

            result = session.encrypt_password("password123")
            assert result == b"encrypted_bytes".hex()

            # Clean up mock
            del sys.modules["win32crypt"]

        # Test error handling
        with mock.patch("platform.system", return_value="Windows"):
            import sys

            win32crypt_mock = mock.MagicMock()
            win32crypt_mock.CryptProtectData.side_effect = Exception("Test error")
            sys.modules["win32crypt"] = win32crypt_mock

            with pytest.raises(Exception) as exc_info:
                session.encrypt_password("password123")
            assert "Error encrypting password: Test error" in str(exc_info.value)

            # Clean up mock
            del sys.modules["win32crypt"]

        session.close()

    @patch("subprocess.Popen")
    def test_clean_certificate_content(self, mock_popen):
        """Test clean_certificate_content method with various certificate content formats"""
        mock_process = MagicMock()
        mock_popen.return_value = mock_process

        credentials = M365Credentials()
        identity = M365IdentityInfo()
        session = M365PowerShell(credentials, identity)

        # Test with clean base64 content
        clean_cert = "MIIDXTCCAkWgAwIBAgIJAJc1HiIAZAiIMA0GCSqGSIb3DQEBBQUAMEUxCzAJBgNV"
        result = session.clean_certificate_content(clean_cert)
        assert result == clean_cert

        # Test with newlines
        cert_with_newlines = "MIIDXTCCAkWgAwIBAgIJAJc1HiIAZAiIMA0GCSqGSIb3DQEBBQUAMEUxCzAJBgNV\nBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldA=="
        expected = "MIIDXTCCAkWgAwIBAgIJAJc1HiIAZAiIMA0GCSqGSIb3DQEBBQUAMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldA=="
        result = session.clean_certificate_content(cert_with_newlines)
        assert result == expected

        # Test with carriage returns
        cert_with_cr = "MIIDXTCCAkWgAwIBAgIJAJc1HiIAZAiIMA0GCSqGSIb3DQEBBQUAMEUxCzAJBgNV\rBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldA=="
        result = session.clean_certificate_content(cert_with_cr)
        assert result == expected

        # Test with spaces
        cert_with_spaces = "MIIDXTCCAkWgAwIBAgIJAJc1HiIAZAiIMA0GCSqGSIb3DQEBBQUAMEUxCzAJBgNV BAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldA=="
        result = session.clean_certificate_content(cert_with_spaces)
        assert result == expected

        # Test with combination of all whitespace types
        cert_mixed = "MIIDXTCCAkWgAwIBAgIJAJc1HiIAZAiIMA0GCSqGSIb3DQEBBQUAMEUxCzAJBgNV\n\r BAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldA=="
        result = session.clean_certificate_content(cert_mixed)
        assert result == expected

        # Test with leading/trailing whitespace
        cert_with_whitespace = "   MIIDXTCCAkWgAwIBAgIJAJc1HiIAZAiIMA0GCSqGSIb3DQEBBQUAMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldA==   "
        result = session.clean_certificate_content(cert_with_whitespace)
        assert result == expected

        session.close()

    @patch("subprocess.Popen")
    def test_init_credential_certificate_auth(self, mock_popen):
        """Test init_credential method with certificate authentication"""
        mock_process = MagicMock()
        mock_popen.return_value = mock_process

        certificate_content = base64.b64encode(b"fake_certificate").decode("utf-8")
        credentials = M365Credentials(
            client_id="test_client_id",
            tenant_id="test_tenant_id",
            certificate_content=certificate_content,
            tenant_domains=["example.com"],
        )
        identity = M365IdentityInfo(tenant_domains=["example.com"])

        # Create session without calling init_credential
        with patch.object(M365PowerShell, "init_credential"):
            session = M365PowerShell(credentials, identity)

        # Mock the execute method
        execute_calls = []

        def mock_execute(command):
            execute_calls.append(command)
            if (
                "New-Object System.Security.Cryptography.X509Certificates.X509Certificate2"
                in command
            ):
                return ""  # No error
            return ""

        session.execute = MagicMock(side_effect=mock_execute)
        session.sanitize = MagicMock(side_effect=lambda x: x)
        session.clean_certificate_content = MagicMock(return_value=certificate_content)

        # Now call init_credential
        session.init_credential(credentials)

        # Verify clean_certificate_content was called
        session.clean_certificate_content.assert_called_once_with(certificate_content)

        # Verify sanitize was called for client_id and tenant_id
        session.sanitize.assert_any_call(credentials.client_id)
        session.sanitize.assert_any_call(credentials.tenant_id)

        # Verify execute was called with correct commands
        session.execute.assert_any_call(
            f'$certBytes = [Convert]::FromBase64String("{certificate_content}")'
        )
        session.execute.assert_any_call(
            "$certificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(,$certBytes)"
        )
        session.execute.assert_any_call(f'$clientID = "{credentials.client_id}"')
        session.execute.assert_any_call(f'$tenantID = "{credentials.tenant_id}"')
        session.execute.assert_any_call(
            f'$tenantDomain = "{credentials.tenant_domains[0]}"'
        )

        session.close()

    @patch("subprocess.Popen")
    def test_init_credential_certificate_auth_creation_error(self, mock_popen):
        """Test init_credential method with certificate authentication when certificate creation fails"""
        mock_process = MagicMock()
        mock_popen.return_value = mock_process

        certificate_content = base64.b64encode(b"invalid_certificate").decode("utf-8")
        credentials = M365Credentials(
            client_id="test_client_id",
            tenant_id="test_tenant_id",
            certificate_content=certificate_content,
            tenant_domains=["example.com"],
        )
        identity = M365IdentityInfo(tenant_domains=["example.com"])

        # Create session without calling init_credential
        with patch.object(M365PowerShell, "init_credential"):
            session = M365PowerShell(credentials, identity)

        # Mock the execute method to simulate certificate creation error
        def mock_execute(command):
            if (
                "New-Object System.Security.Cryptography.X509Certificates.X509Certificate2"
                in command
            ):
                return "Certificate creation failed: Invalid certificate format"
            return ""

        session.execute = MagicMock(side_effect=mock_execute)
        session.sanitize = MagicMock(side_effect=lambda x: x)
        session.clean_certificate_content = MagicMock(return_value=certificate_content)

        with pytest.raises(M365CertificateCreationError) as exc_info:
            session.init_credential(credentials)

        # The actual error message format from the exception
        assert "Failed to create X.509 certificate object" in str(exc_info.value)

        session.close()

    @patch("subprocess.Popen")
    def test_test_exchange_certificate_connection_success(self, mock_popen):
        """Test test_exchange_certificate_connection method with successful connection"""
        mock_process = MagicMock()
        mock_popen.return_value = mock_process

        credentials = M365Credentials()
        identity = M365IdentityInfo()
        session = M365PowerShell(credentials, identity)

        # Mock successful Exchange connection
        session.execute = MagicMock(
            return_value="Connected successfully https://aka.ms/exov3-module"
        )

        result = session.test_exchange_certificate_connection()
        assert result is True

        session.execute.assert_called_once_with(
            "Connect-ExchangeOnline -Certificate $certificate -AppId $clientID -Organization $tenantDomain"
        )

        session.close()

    @patch("subprocess.Popen")
    def test_test_exchange_certificate_connection_failure(self, mock_popen):
        """Test test_exchange_certificate_connection method with failed connection"""
        mock_process = MagicMock()
        mock_popen.return_value = mock_process

        credentials = M365Credentials()
        identity = M365IdentityInfo()
        session = M365PowerShell(credentials, identity)

        # Mock failed Exchange connection
        session.execute = MagicMock(
            return_value="Connection failed: Authentication error"
        )

        result = session.test_exchange_certificate_connection()
        assert result is False

        session.execute.assert_called_once_with(
            "Connect-ExchangeOnline -Certificate $certificate -AppId $clientID -Organization $tenantDomain"
        )

        session.close()

    @patch("subprocess.Popen")
    def test_test_teams_certificate_connection_success(self, mock_popen):
        """Test test_teams_certificate_connection method with successful connection"""
        mock_process = MagicMock()
        mock_popen.return_value = mock_process

        credentials = M365Credentials()
        identity = M365IdentityInfo(identity_id="test_identity_id")

        # Create session without calling init_credential
        with patch.object(M365PowerShell, "init_credential"):
            session = M365PowerShell(credentials, identity)

        # Mock successful Teams connection - the method returns bool
        def mock_execute_side_effect(command):
            if "Connect-MicrosoftTeams" in command:
                # Return result that contains the identity_id for success
                return "Connected successfully test_identity_id"
            return ""

        session.execute = MagicMock(side_effect=mock_execute_side_effect)

        result = session.test_teams_certificate_connection()
        assert result is True

        session.execute.assert_called_once_with(
            "Connect-MicrosoftTeams -Certificate $certificate -ApplicationId $clientID -TenantId $tenantID"
        )

        session.close()

    @patch("subprocess.Popen")
    def test_test_teams_certificate_connection_failure(self, mock_popen):
        """Test test_teams_certificate_connection method with failed connection"""
        mock_process = MagicMock()
        mock_popen.return_value = mock_process

        credentials = M365Credentials()
        identity = M365IdentityInfo()
        session = M365PowerShell(credentials, identity)

        # Mock failed Teams connection
        def mock_execute_side_effect(command, json_parse=False):
            if "Connect-MicrosoftTeams" in command:
                raise Exception("Connection failed: Authentication error")
            return ""

        session.execute = MagicMock(side_effect=mock_execute_side_effect)

        # Should raise exception on connection failure
        with pytest.raises(Exception) as exc_info:
            session.test_teams_certificate_connection()

        assert "Connection failed: Authentication error" in str(exc_info.value)

        session.close()

    @patch("subprocess.Popen")
    def test_test_credentials_certificate_auth_success(self, mock_popen):
        """Test test_credentials method with certificate authentication - successful"""
        mock_process = MagicMock()
        mock_popen.return_value = mock_process

        certificate_content = base64.b64encode(b"fake_certificate").decode("utf-8")
        credentials = M365Credentials(
            client_id="test_client_id", certificate_content=certificate_content
        )
        identity = M365IdentityInfo()

        # Create session without calling init_credential
        with patch.object(M365PowerShell, "init_credential"):
            session = M365PowerShell(credentials, identity)

        # Mock successful certificate connections
        # Note: The actual implementation uses "or" so if teams succeeds, exchange won't be called
        session.test_teams_certificate_connection = MagicMock(return_value=True)
        session.test_exchange_certificate_connection = MagicMock(return_value=True)

        result = session.test_credentials(credentials)
        assert result is True

        session.test_teams_certificate_connection.assert_called_once()
        # Exchange connection should NOT be called if teams connection succeeds (due to "or" logic)
        session.test_exchange_certificate_connection.assert_not_called()

        session.close()

    @patch("subprocess.Popen")
    def test_test_credentials_certificate_auth_failure(self, mock_popen):
        """Test test_credentials method with certificate authentication - failure"""
        mock_process = MagicMock()
        mock_popen.return_value = mock_process

        certificate_content = base64.b64encode(b"fake_certificate").decode("utf-8")
        credentials = M365Credentials(
            client_id="test_client_id", certificate_content=certificate_content
        )
        identity = M365IdentityInfo()

        # Create session without calling init_credential
        with patch.object(M365PowerShell, "init_credential"):
            session = M365PowerShell(credentials, identity)

        # Mock failed certificate connections - teams fails, so exchange is tried
        session.test_teams_certificate_connection = MagicMock(return_value=False)
        session.test_exchange_certificate_connection = MagicMock(return_value=False)

        result = session.test_credentials(credentials)
        assert result is True  # Method always returns True after the try block

        session.close()

    @patch("subprocess.Popen")
    def test_connect_microsoft_teams_certificate_auth(self, mock_popen):
        """Test connect_microsoft_teams method with certificate authentication"""
        mock_process = MagicMock()
        mock_popen.return_value = mock_process

        credentials = M365Credentials()
        identity = M365IdentityInfo()
        session = M365PowerShell(credentials, identity)

        # Mock certificate variable check and teams connection
        execute_calls = []

        def mock_execute_side_effect(command, json_parse=False):
            execute_calls.append(command)
            if "Write-Output $certificate" in command:
                return "certificate_content"  # Non-empty means certificate exists
            elif "Connect-MicrosoftTeams" in command:
                return {"TenantId": "test-tenant-id", "Account": "test-account"}
            return ""

        session.execute = MagicMock(side_effect=mock_execute_side_effect)
        session.test_teams_certificate_connection = MagicMock(
            return_value={"success": True}
        )

        result = session.connect_microsoft_teams()
        assert result == {"success": True}

        session.test_teams_certificate_connection.assert_called_once()

        session.close()

    @patch("subprocess.Popen")
    def test_connect_exchange_online_certificate_auth(self, mock_popen):
        """Test connect_exchange_online method with certificate authentication"""
        mock_process = MagicMock()
        mock_popen.return_value = mock_process

        credentials = M365Credentials()
        identity = M365IdentityInfo()
        session = M365PowerShell(credentials, identity)

        # Mock certificate variable check and exchange connection
        execute_calls = []

        def mock_execute_side_effect(command, json_parse=False):
            execute_calls.append(command)
            if "Write-Output $certificate" in command:
                return "certificate_content"  # Non-empty means certificate exists
            return ""

        session.execute = MagicMock(side_effect=mock_execute_side_effect)
        session.test_exchange_certificate_connection = MagicMock(return_value=True)

        result = session.connect_exchange_online()
        assert result is True

        session.test_exchange_certificate_connection.assert_called_once()

        session.close()

    @patch("subprocess.Popen")
    def test_clean_certificate_content_basic(self, mock_popen):
        """Test clean_certificate_content method with basic certificate content"""
        mock_process = MagicMock()
        mock_popen.return_value = mock_process
        mock_process.returncode = 0

        session = M365PowerShell(
            M365Credentials(
                client_id="test_client_id",
                client_secret="test_secret",
                tenant_id="test_tenant_id",
                tenant_domains=["contoso.com"],
            ),
            M365IdentityInfo(
                tenant_id="test_tenant_id",
                tenant_domain="contoso.com",
                tenant_domains=["contoso.com"],
                identity_id="test_identity_id",
                identity_type="Service Principal",
            ),
        )

        # Test basic certificate content cleaning
        cert_content = "LS0tLS1CRUdJTi\nBFUlRJRklD\rQVRFLS0tLS0\n"
        expected = "LS0tLS1CRUdJTiBFUlRJRklDQVRFLS0tLS0"

        result = session.clean_certificate_content(cert_content)

        assert result == expected
        session.close()

    @patch("subprocess.Popen")
    def test_clean_certificate_content_with_spaces(self, mock_popen):
        """Test clean_certificate_content method with spaces in certificate content"""
        mock_process = MagicMock()
        mock_popen.return_value = mock_process
        mock_process.returncode = 0

        session = M365PowerShell(
            M365Credentials(
                client_id="test_client_id",
                client_secret="test_secret",
                tenant_id="test_tenant_id",
                tenant_domains=["contoso.com"],
            ),
            M365IdentityInfo(
                tenant_id="test_tenant_id",
                tenant_domain="contoso.com",
                tenant_domains=["contoso.com"],
                identity_id="test_identity_id",
                identity_type="Service Principal",
            ),
        )

        # Test certificate content with spaces
        cert_content = "  LS0tLS1CRUdJTi BFUlRJRklD QVRFLS0tLS0  "
        expected = "LS0tLS1CRUdJTiBFUlRJRklDQVRFLS0tLS0"

        result = session.clean_certificate_content(cert_content)

        assert result == expected
        session.close()

    @patch("subprocess.Popen")
    def test_clean_certificate_content_empty(self, mock_popen):
        """Test clean_certificate_content method with empty certificate content"""
        mock_process = MagicMock()
        mock_popen.return_value = mock_process
        mock_process.returncode = 0

        session = M365PowerShell(
            M365Credentials(
                client_id="test_client_id",
                client_secret="test_secret",
                tenant_id="test_tenant_id",
                tenant_domains=["contoso.com"],
            ),
            M365IdentityInfo(
                tenant_id="test_tenant_id",
                tenant_domain="contoso.com",
                tenant_domains=["contoso.com"],
                identity_id="test_identity_id",
                identity_type="Service Principal",
            ),
        )

        # Test empty certificate content
        cert_content = ""
        expected = ""

        result = session.clean_certificate_content(cert_content)

        assert result == expected
        session.close()

    @patch("subprocess.Popen")
    def test_init_credential_certificate_auth_with_domains(self, mock_popen):
        """Test init_credential method with certificate authentication and tenant domains"""
        certificate_content = base64.b64encode(b"fake_certificate").decode("utf-8")

        mock_process = MagicMock()
        mock_popen.return_value = mock_process
        mock_process.returncode = 0

        executed_commands = []

        def mock_execute(command):
            executed_commands.append(command)
            if "Error creating certificate" in command:
                return None  # No error
            return ""

        # Create session with non-certificate credentials first
        session = M365PowerShell(
            M365Credentials(
                client_id="test_client_id",
                client_secret="test_secret",
                tenant_id="test_tenant_id",
                tenant_domains=["contoso.com", "subdomain.contoso.com"],
            ),
            M365IdentityInfo(
                tenant_id="test_tenant_id",
                tenant_domain="contoso.com",
                tenant_domains=["contoso.com", "subdomain.contoso.com"],
                identity_id="test_identity_id",
                identity_type="Service Principal with Certificate",
            ),
        )

        # Mock methods before calling init_credential
        session.execute = MagicMock(side_effect=mock_execute)
        session.sanitize = MagicMock(side_effect=lambda x: x)
        session.clean_certificate_content = MagicMock(return_value=certificate_content)

        # Now test certificate authentication
        session.init_credential(
            M365Credentials(
                client_id="test_client_id",
                tenant_id="test_tenant_id",
                certificate_content=certificate_content,
                tenant_domains=["contoso.com", "subdomain.contoso.com"],
            )
        )

        # Verify that certificate content was cleaned
        session.clean_certificate_content.assert_called_once_with(certificate_content)

        # Verify certificate creation commands were executed
        assert any(
            "$certBytes = [Convert]::FromBase64String" in cmd
            for cmd in executed_commands
        )
        assert any(
            "$certificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2"
            in cmd
            for cmd in executed_commands
        )
        assert any('$clientID = "test_client_id"' in cmd for cmd in executed_commands)
        assert any('$tenantID = "test_tenant_id"' in cmd for cmd in executed_commands)
        assert any('$tenantDomain = "contoso.com"' in cmd for cmd in executed_commands)

        session.close()

    @patch("subprocess.Popen")
    def test_test_credentials_certificate_auth_with_or_logic(self, mock_popen):
        """Test test_credentials method with certificate auth using OR logic between Teams and Exchange"""
        certificate_content = base64.b64encode(b"fake_certificate").decode("utf-8")

        mock_process = MagicMock()
        mock_popen.return_value = mock_process
        mock_process.returncode = 0

        # Create session with non-certificate credentials first
        session = M365PowerShell(
            M365Credentials(
                client_id="test_client_id",
                client_secret="test_secret",
                tenant_id="test_tenant_id",
                tenant_domains=["contoso.com"],
            ),
            M365IdentityInfo(
                tenant_id="test_tenant_id",
                tenant_domain="contoso.com",
                tenant_domains=["contoso.com"],
                identity_id="test_identity_id",
                identity_type="Service Principal with Certificate",
            ),
        )

        # Mock that Teams connection fails but Exchange succeeds
        session.test_teams_certificate_connection = MagicMock(return_value=False)
        session.test_exchange_certificate_connection = MagicMock(return_value=True)

        result = session.test_credentials(
            M365Credentials(
                client_id="test_client_id",
                tenant_id="test_tenant_id",
                certificate_content=certificate_content,
                tenant_domains=["contoso.com"],
            )
        )

        assert result is True
        session.test_teams_certificate_connection.assert_called_once()
        session.test_exchange_certificate_connection.assert_called_once()

        session.close()

    @patch("subprocess.Popen")
    def test_test_credentials_certificate_auth_both_fail(self, mock_popen):
        """Test test_credentials method with certificate auth when both Teams and Exchange fail"""
        certificate_content = base64.b64encode(b"fake_certificate").decode("utf-8")

        mock_process = MagicMock()
        mock_popen.return_value = mock_process
        mock_process.returncode = 0

        # Create session with non-certificate credentials first
        session = M365PowerShell(
            M365Credentials(
                client_id="test_client_id",
                client_secret="test_secret",
                tenant_id="test_tenant_id",
                tenant_domains=["contoso.com"],
            ),
            M365IdentityInfo(
                tenant_id="test_tenant_id",
                tenant_domain="contoso.com",
                tenant_domains=["contoso.com"],
                identity_id="test_identity_id",
                identity_type="Service Principal with Certificate",
            ),
        )

        # Mock that both connections fail
        session.test_teams_certificate_connection = MagicMock(return_value=False)
        session.test_exchange_certificate_connection = MagicMock(return_value=False)

        # Even when both fail, the method should return True (this is the intended logic)
        result = session.test_credentials(
            M365Credentials(
                client_id="test_client_id",
                tenant_id="test_tenant_id",
                certificate_content=certificate_content,
                tenant_domains=["contoso.com"],
            )
        )

        assert result is True
        session.test_teams_certificate_connection.assert_called_once()
        session.test_exchange_certificate_connection.assert_called_once()

        session.close()
