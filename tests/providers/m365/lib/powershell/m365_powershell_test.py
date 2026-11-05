import base64
from unittest.mock import MagicMock, call, patch

import pytest

from prowler.lib.powershell.powershell import PowerShellSession
from prowler.providers.m365.exceptions.exceptions import M365CertificateCreationError
from prowler.providers.m365.lib.powershell.m365_powershell import M365PowerShell
from prowler.providers.m365.models import M365Credentials, M365IdentityInfo


class Testm365PowerShell:
    @patch("subprocess.Popen")
    def test_init(self, mock_popen):
        mock_process = MagicMock()
        mock_popen.return_value = mock_process
        credentials = M365Credentials(
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

        with patch.object(M365PowerShell, "init_credential") as mock_init_credential:
            session = M365PowerShell(credentials, identity)

            mock_popen.assert_called_once()
            mock_init_credential.assert_called_once_with(credentials)
            assert session.process == mock_process
            assert session.END == "<END>"
            session.close()

    @patch("subprocess.Popen")
    def test_sanitize(self, _):
        credentials = M365Credentials(
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
            client_id="test_client_id",
            client_secret="test_client_secret",
            tenant_id="test_tenant_id",
        )
        identity = M365IdentityInfo(
            identity_id="test_id",
            identity_type="Service Principal",
            tenant_id="test_tenant",
            tenant_domain="example.com",
            tenant_domains=["example.com"],
            location="test_location",
        )
        with patch.object(M365PowerShell, "init_credential") as mock_init:
            session = M365PowerShell(credentials, identity)
            mock_init.assert_called_once_with(credentials)

        session.execute = MagicMock()

        # Call original init_credential to verify application authentication setup
        M365PowerShell.init_credential(session, credentials)

        session.execute.assert_any_call("$clientID = 'test_client_id'")
        session.execute.assert_any_call("$clientSecret = 'test_client_secret'")
        session.execute.assert_any_call("$tenantID = 'test_tenant_id'")
        session.execute.assert_any_call(
            '$graphtokenBody = @{ Grant_Type = "client_credentials"; Scope = "https://graph.microsoft.com/.default"; Client_Id = $clientID; Client_Secret = $clientSecret }'
        )
        session.execute.assert_any_call(
            '$graphToken = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$tenantID/oauth2/v2.0/token" -Method POST -Body $graphtokenBody | Select-Object -ExpandProperty Access_Token'
        )
        session.close()

    @patch("subprocess.Popen")
    def test_init_credential_special_chars_in_secret(self, mock_popen):
        """Test that secrets with $, !, #, and ' are preserved via single-quote escaping."""
        mock_process = MagicMock()
        mock_popen.return_value = mock_process
        credentials = M365Credentials(
            client_id="test_client_id",
            client_secret="Pa$$w0rd!#'",
            tenant_id="test_tenant_id",
        )
        identity = M365IdentityInfo(
            identity_id="test_id",
            identity_type="Service Principal",
            tenant_id="test_tenant",
            tenant_domain="example.com",
            tenant_domains=["example.com"],
            location="test_location",
        )
        with patch.object(M365PowerShell, "init_credential"):
            session = M365PowerShell(credentials, identity)

        session.execute = MagicMock()
        M365PowerShell.init_credential(session, credentials)

        # Single quotes prevent PowerShell $$ expansion;
        # embedded ' is escaped as '' per PowerShell convention
        session.execute.assert_any_call("$clientSecret = 'Pa$$w0rd!#'''")

    @pytest.mark.parametrize(
        "secret, expected_command",
        [
            # Plain secret: single quotes behave like the old double quotes.
            ("simplesecret", "$clientSecret = 'simplesecret'"),
            # $ must NOT expand as a PowerShell variable.
            ("Pa$$w0rd", "$clientSecret = 'Pa$$w0rd'"),
            # $(...) subexpression must stay literal and never execute.
            ("a$(whoami)b", "$clientSecret = 'a$(whoami)b'"),
            # ${var} expansion must stay literal too.
            ("a${env:PATH}b", "$clientSecret = 'a${env:PATH}b'"),
            # Backtick is a literal char inside single quotes (not an escape).
            ("pass`word", "$clientSecret = 'pass`word'"),
            # Double quotes are literal inside single quotes.
            ('pa"ss"word', "$clientSecret = 'pa\"ss\"word'"),
            # A single quote is doubled per PowerShell escaping rules.
            ("O'Brien", "$clientSecret = 'O''Brien'"),
            # Consecutive single quotes each get doubled.
            ("a''b", "$clientSecret = 'a''''b'"),
            # A payload with quotes and metacharacters stays a single literal
            # string and cannot break out of the quoting.
            (
                "'; Remove-Item -Recurse -Force; '",
                "$clientSecret = '''; Remove-Item -Recurse -Force; '''",
            ),
            # Other shell metacharacters are preserved verbatim (no sanitize()).
            ("p@ss!#%&;w0rd", "$clientSecret = 'p@ss!#%&;w0rd'"),
            # Newline embedded in the secret is preserved verbatim.
            ("line1\nline2", "$clientSecret = 'line1\nline2'"),
            # Empty secret renders an empty single-quoted string.
            ("", "$clientSecret = ''"),
            # None secret is coerced to an empty single-quoted string.
            (None, "$clientSecret = ''"),
        ],
    )
    @patch("subprocess.Popen")
    def test_init_credential_secret_escaping_edge_cases(
        self, mock_popen, secret, expected_command
    ):
        """The client_secret is single-quote escaped, preserving every special
        character verbatim with no PowerShell expansion or subexpression
        evaluation."""
        mock_process = MagicMock()
        mock_popen.return_value = mock_process
        credentials = M365Credentials(
            client_id="test_client_id",
            client_secret=secret,
            tenant_id="test_tenant_id",
        )
        identity = M365IdentityInfo(
            identity_id="test_id",
            identity_type="Service Principal",
            tenant_id="test_tenant",
            tenant_domain="example.com",
            tenant_domains=["example.com"],
            location="test_location",
        )
        with patch.object(M365PowerShell, "init_credential"):
            session = M365PowerShell(credentials, identity)

        session.execute = MagicMock()
        M365PowerShell.init_credential(session, credentials)

        session.execute.assert_any_call(expected_command)

    @patch("subprocess.Popen")
    def test_init_credential_sanitizes_client_and_tenant_id(self, mock_popen):
        """client_id and tenant_id are sanitized in the Application Auth path,
        stripping shell metacharacters while keeping UUID-safe characters."""
        mock_process = MagicMock()
        mock_popen.return_value = mock_process
        credentials = M365Credentials(
            client_id="abc-123; Remove-Item",
            client_secret="secret",
            tenant_id="def-456 && whoami",
        )
        identity = M365IdentityInfo(
            identity_id="test_id",
            identity_type="Service Principal",
            tenant_id="test_tenant",
            tenant_domain="example.com",
            tenant_domains=["example.com"],
            location="test_location",
        )
        with patch.object(M365PowerShell, "init_credential"):
            session = M365PowerShell(credentials, identity)

        session.execute = MagicMock()
        M365PowerShell.init_credential(session, credentials)

        # sanitize() removes ';', spaces and '&' but keeps letters, digits and '-'.
        session.execute.assert_any_call("$clientID = 'abc-123Remove-Item'")
        session.execute.assert_any_call("$tenantID = 'def-456whoami'")

    @patch("subprocess.Popen")
    def test_remove_ansi(self, mock_popen):
        credentials = M365Credentials(
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
        credentials = M365Credentials(
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
        credentials = M365Credentials(
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
        credentials = M365Credentials(
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
        credentials = M365Credentials(
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

        session.close()

        mock_process.stdin.flush.assert_called_once()
        mock_process.terminate.assert_called_once()

    @patch("subprocess.Popen")
    def test_initialize_m365_powershell_modules_success(self, mock_popen):
        """Test initialize_m365_powershell_modules when all modules are successfully initialized"""
        mock_process = MagicMock()
        mock_popen.return_value = mock_process

        # Mock the execute method to simulate successful module installation
        def mock_execute(command, *args, **_kwargs):
            if "Get-Module" in command:
                return None  # Module not installed
            elif "Install-Module" in command:
                return None  # Installation successful
            elif 'Import-Module "PnP.PowerShell"' in command:
                return "3.4.1"
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
            # Verify success messages were logged
            mock_info.assert_any_call(
                "Successfully installed module ExchangeOnlineManagement"
            )
            mock_info.assert_any_call("Successfully installed module MicrosoftTeams")
            mock_info.assert_any_call(
                "Successfully installed module PnP.PowerShell 3.4.1"
            )
            commands = [
                mock_call.args[0] for mock_call in mock_execute_obj.call_args_list
            ]
            assert any(
                "Install-Module PnP.PowerShell" in command
                and "-RequiredVersion 3.4.1" in command
                for command in commands
            )
            assert any(
                "Get-Module -ListAvailable PnP.PowerShell" in command
                and "[version]'3.4.1'" in command
                for command in commands
            )
            assert any(
                'Import-Module "PnP.PowerShell"' in command
                and "-RequiredVersion 3.4.1" in command
                for command in commands
            )

    @patch("subprocess.Popen")
    def test_initialize_m365_powershell_modules_failure(self, mock_popen):
        """Test initialize_m365_powershell_modules when module initialization fails"""
        mock_process = MagicMock()
        mock_popen.return_value = mock_process

        # Mock the execute method to simulate installation failure
        def mock_execute(command, *args, **_kwargs):
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
    def test_initialize_m365_powershell_modules_imports_installed_pnp_module(
        self, mock_popen
    ):
        """The pinned PnP module is imported even when it is already installed."""
        mock_popen.return_value = MagicMock()

        def execute(command, *args, **_kwargs):
            if 'Import-Module "PnP.PowerShell"' in command:
                return "3.4.1"
            return "Installed"

        with patch.object(
            PowerShellSession, "execute", side_effect=execute
        ) as mock_execute:
            from prowler.providers.m365.lib.powershell.m365_powershell import (
                initialize_m365_powershell_modules,
            )

            assert initialize_m365_powershell_modules() is True

        commands = [mock_call.args[0] for mock_call in mock_execute.call_args_list]
        assert any(
            'Import-Module "PnP.PowerShell"' in command
            and "-RequiredVersion 3.4.1" in command
            for command in commands
        )
        assert all(
            "Install-Module PnP.PowerShell" not in command for command in commands
        )
        pnp_import_call = next(
            mock_call
            for mock_call in mock_execute.call_args_list
            if 'Import-Module "PnP.PowerShell"' in mock_call.args[0]
        )
        assert "timeout" not in pnp_import_call.kwargs

    @patch("subprocess.Popen")
    def test_initialize_m365_powershell_modules_fails_when_pnp_import_fails(
        self, mock_popen
    ):
        """PnP import must be validated before initialization reports success."""
        mock_popen.return_value = MagicMock()

        def execute(command, *args, **_kwargs):
            if "Get-Module" in command:
                return "" if "PnP.PowerShell" in command else "Installed"
            return ""

        with patch.object(PowerShellSession, "execute", side_effect=execute):
            from prowler.providers.m365.lib.powershell.m365_powershell import (
                initialize_m365_powershell_modules,
            )

            assert initialize_m365_powershell_modules() is False

    @patch("subprocess.Popen")
    def test_main_success(self, mock_popen):
        """Test main() function when module initialization is successful"""
        mock_process = MagicMock()
        mock_popen.return_value = mock_process

        # Mock the execute method to simulate successful module installation
        def mock_execute(command, *args, **_kwargs):
            if "Get-Module" in command:
                return None  # Module not installed
            elif "Install-Module" in command:
                return None  # Installation successful
            elif 'Import-Module "PnP.PowerShell"' in command:
                return "3.4.1"
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
            assert mock_info.call_count == 5
            mock_info.assert_has_calls(
                [
                    call("Successfully installed module ExchangeOnlineManagement"),
                    call("Successfully installed module MicrosoftTeams"),
                    call("Successfully installed module MSAL.PS"),
                    call("Successfully installed module PnP.PowerShell 3.4.1"),
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
        def mock_execute(command, *args, **_kwargs):
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
    def test_test_teams_connection_success(self, mock_popen):
        """Test test_teams_connection when token is valid"""
        mock_process = MagicMock()
        mock_popen.return_value = mock_process
        credentials = M365Credentials(
            client_id="test_client_id",
            client_secret="test_client_secret",
            tenant_id="test_tenant_id",
        )
        identity = M365IdentityInfo(
            identity_id="test_id",
            identity_type="Application",
            tenant_id="test_tenant",
            tenant_domain="example.com",
            tenant_domains=["example.com"],
            location="test_location",
        )
        session = M365PowerShell(credentials, identity)

        session.execute = MagicMock(side_effect=[None, ""])
        session.execute_connect = MagicMock(return_value="")

        result = session.test_teams_connection()

        assert result is True
        assert session.execute.call_count == 2
        session.execute_connect.assert_called_once_with(
            'Connect-MicrosoftTeams -AccessTokens @("$graphToken","$teamsToken")'
        )
        session.close()

    @patch("subprocess.Popen")
    def test_test_teams_connection_missing_permissions(self, mock_popen):
        """Test test_teams_connection when token lacks required permissions"""
        mock_process = MagicMock()
        mock_popen.return_value = mock_process
        credentials = M365Credentials(
            client_id="test_client_id",
            client_secret="test_client_secret",
            tenant_id="test_tenant_id",
        )
        identity = M365IdentityInfo(
            identity_id="test_id",
            identity_type="Application",
            tenant_id="test_tenant",
            tenant_domain="example.com",
            tenant_domains=["example.com"],
            location="test_location",
        )
        session = M365PowerShell(credentials, identity)

        session.execute = MagicMock(side_effect=[None, "Permission denied"])
        session.execute_connect = MagicMock()

        with patch("prowler.lib.logger.logger.error") as mock_error:
            result = session.test_teams_connection()

        assert result is False
        mock_error.assert_called_once_with(
            "Microsoft Teams connection failed: Permission denied"
        )
        session.execute_connect.assert_not_called()
        session.close()

    @patch("subprocess.Popen")
    def test_test_teams_connection_exception(self, mock_popen):
        """Test test_teams_connection when an exception occurs"""
        mock_process = MagicMock()
        mock_popen.return_value = mock_process
        credentials = M365Credentials(
            client_id="test_client_id",
            client_secret="test_client_secret",
            tenant_id="test_tenant_id",
        )
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
        credentials = M365Credentials(
            client_id="test_client_id",
            client_secret="test_client_secret",
            tenant_id="test_tenant_id",
        )
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
        def mock_execute(command, *args, **_kwargs):
            if "Write-Output $exchangeToken" in command:
                return "valid_exchange_token"
            return None

        session.execute = MagicMock(side_effect=mock_execute)
        session.execute_connect = MagicMock(return_value=None)
        # Mock MSAL token decode to return proper permissions
        mock_decode_msal_token.return_value = {"roles": ["Exchange.ManageAsApp"]}

        result = session.test_exchange_connection()

        assert result is True
        assert session.execute.call_count == 3
        # The secret must be referenced as a bare PowerShell variable. Wrapping it
        # in double quotes ("$clientSecret") would re-expand special chars that were
        # correctly escaped during assignment, so assert the exact command.
        session.execute.assert_any_call(
            "$SecureSecret = ConvertTo-SecureString $clientSecret -AsPlainText -Force"
        )
        session.execute_connect.assert_called_once_with(
            'Connect-ExchangeOnline -AccessToken $exchangeToken.AccessToken -Organization "$tenantID"'
        )
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
        credentials = M365Credentials(
            client_id="test_client_id",
            client_secret="test_client_secret",
            tenant_id="test_tenant_id",
        )
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
        def mock_execute(command, *args, **_kwargs):
            if "Write-Output $exchangeToken" in command:
                return "valid_exchange_token"
            return None

        session.execute = MagicMock(side_effect=mock_execute)
        session.execute_connect = MagicMock(return_value=None)
        # Mock MSAL token decode to return missing required permission
        mock_decode_msal_token.return_value = {"roles": ["other_permission"]}

        with patch("prowler.lib.logger.logger.error") as mock_error:
            result = session.test_exchange_connection()

        assert result is False
        session.execute_connect.assert_not_called()
        mock_error.assert_called_once_with(
            "Exchange Online connection failed: Please check your permissions and try again."
        )
        session.close()

    @patch("subprocess.Popen")
    def test_test_exchange_connection_exception(self, mock_popen):
        """Test test_exchange_connection when an exception occurs"""
        mock_process = MagicMock()
        mock_popen.return_value = mock_process
        credentials = M365Credentials(
            client_id="test_client_id",
            client_secret="test_client_secret",
            tenant_id="test_tenant_id",
        )
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
    def test_clean_certificate_content(self, mock_popen):
        """Test clean_certificate_content method with various certificate content formats"""
        mock_process = MagicMock()
        mock_popen.return_value = mock_process

        credentials = M365Credentials()
        identity = M365IdentityInfo(identity_id="expected-id")
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
        identity = M365IdentityInfo(identity_id="expected-id")
        session = M365PowerShell(credentials, identity)

        session.execute_connect = MagicMock(
            return_value="Connected successfully https://aka.ms/exov3-module"
        )

        result = session.test_exchange_certificate_connection()
        assert result is True

        session.execute_connect.assert_called_once_with(
            "Connect-ExchangeOnline -Certificate $certificate -AppId $clientID -Organization $tenantDomain"
        )

        session.close()

    @patch("subprocess.Popen")
    def test_test_exchange_certificate_connection_failure(self, mock_popen):
        """Test test_exchange_certificate_connection method with failed connection"""
        mock_process = MagicMock()
        mock_popen.return_value = mock_process

        credentials = M365Credentials()
        identity = M365IdentityInfo(identity_id="expected-id")
        session = M365PowerShell(credentials, identity)

        session.execute_connect = MagicMock(
            return_value="Connection failed: Authentication error"
        )

        with patch("prowler.lib.logger.logger.error") as mock_error:
            result = session.test_exchange_certificate_connection()

        assert result is False

        session.execute_connect.assert_called_once_with(
            "Connect-ExchangeOnline -Certificate $certificate -AppId $clientID -Organization $tenantDomain"
        )
        mock_error.assert_called_once_with(
            "Exchange Online Certificate connection failed: Connection failed: Authentication error"
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
        session.execute_connect = MagicMock(
            return_value="Connected successfully test_identity_id"
        )

        result = session.test_teams_certificate_connection()
        assert result is True

        session.execute_connect.assert_called_once_with(
            "Connect-MicrosoftTeams -Certificate $certificate -ApplicationId $clientID -TenantId $tenantID"
        )

        session.close()

    @patch("subprocess.Popen")
    def test_test_teams_certificate_connection_failure(self, mock_popen):
        """Test test_teams_certificate_connection method with failed connection"""
        mock_process = MagicMock()
        mock_popen.return_value = mock_process

        credentials = M365Credentials()
        identity = M365IdentityInfo(identity_id="expected-id")
        session = M365PowerShell(credentials, identity)

        session.execute_connect = MagicMock(return_value="Connection failed")

        with patch("prowler.lib.logger.logger.error") as mock_error:
            result = session.test_teams_certificate_connection()

        assert result is False
        session.execute_connect.assert_called_once_with(
            "Connect-MicrosoftTeams -Certificate $certificate -ApplicationId $clientID -TenantId $tenantID"
        )
        mock_error.assert_called_once_with(
            "Microsoft Teams Certificate connection failed: Connection failed"
        )

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

        def mock_execute_side_effect(command):
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

        def mock_execute_side_effect(command):
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

    @pytest.mark.parametrize(
        "region,tenant_domain,azure_environment,admin_url",
        [
            (
                "M365Global",
                "contoso.onmicrosoft.com",
                "Production",
                "https://contoso-admin.sharepoint.com",
            ),
            (
                "M365China",
                "contoso.partner.onmschina.cn",
                "China",
                "https://contoso-admin.sharepoint.cn",
            ),
            (
                "M365USGovernment",
                "contoso.onmicrosoft.us",
                "USGovernmentHigh",
                "https://contoso-admin.sharepoint.us",
            ),
        ],
    )
    @patch("subprocess.Popen")
    def test_connect_sharepoint_online_certificate_auth(
        self,
        mock_popen,
        region,
        tenant_domain,
        azure_environment,
        admin_url,
    ):
        """Certificate auth uses validated tenant and sovereign-cloud settings."""
        mock_popen.return_value = MagicMock()
        session = M365PowerShell(
            M365Credentials(),
            M365IdentityInfo(tenant_domains=[tenant_domain]),
        )
        session.execute = MagicMock(
            side_effect=lambda command, **_: (
                "certificate_content"
                if "Write-Output $certificateBase64" in command
                else ""
            )
        )
        session.execute_connect = MagicMock(return_value="Connected")

        assert session.connect_sharepoint_online(region) is True

        commands = [mock_call.args[0] for mock_call in session.execute.call_args_list]
        connect_command = session.execute_connect.call_args.args[0]
        assert any(admin_url in command for command in commands)
        assert any(tenant_domain in command for command in commands)
        assert "Connect-PnPOnline" in connect_command
        assert "-CertificateBase64Encoded $certificateBase64" in connect_command
        assert "-ClientId $clientID" in connect_command
        assert "-ReturnConnection" in connect_command
        assert "-ValidateConnection" in connect_command
        assert "-ErrorAction Stop" in connect_command
        assert f"-AzureEnvironment {azure_environment}" in connect_command
        assert "-Interactive" not in connect_command
        assert "-ClientSecret" not in connect_command
        session.close()

    @patch("subprocess.Popen")
    def test_connect_sharepoint_online_client_secret_skips_without_prompt(
        self, mock_popen
    ):
        """Client-secret auth skips PnP enrichment without starting a prompt."""
        mock_popen.return_value = MagicMock()
        session = M365PowerShell(M365Credentials(), M365IdentityInfo())
        session.execute = MagicMock(return_value="")
        session.execute_connect = MagicMock()

        assert session.connect_sharepoint_online("M365Global") is False
        session.execute_connect.assert_not_called()
        session.close()

    @patch("subprocess.Popen")
    def test_connect_sharepoint_online_skips_when_pnp_initialization_failed(
        self, mock_popen
    ):
        """Failed PnP initialization disables only SharePoint enrichment."""
        mock_popen.return_value = MagicMock()
        session = M365PowerShell(
            M365Credentials(pnp_powershell_ready=False),
            M365IdentityInfo(tenant_domains=["contoso.onmicrosoft.com"]),
        )
        session.execute = MagicMock(return_value="certificate_content")
        session.execute_connect = MagicMock(return_value="Connected")

        assert session.connect_sharepoint_online("M365Global") is False
        session.execute.assert_not_called()
        session.execute_connect.assert_not_called()
        session.close()

    @patch("subprocess.Popen")
    def test_connect_sharepoint_online_rejects_unvalidated_tenant_domain(
        self, mock_popen
    ):
        """Custom domains cannot be used to guess the SharePoint admin hostname."""
        mock_popen.return_value = MagicMock()
        session = M365PowerShell(
            M365Credentials(),
            M365IdentityInfo(tenant_domains=["contoso.example"]),
        )
        session.execute = MagicMock(return_value="certificate_content")
        session.execute_connect = MagicMock()

        assert session.connect_sharepoint_online("M365Global") is False
        session.execute_connect.assert_not_called()
        session.close()

    @pytest.mark.parametrize(
        "connection_result", ["", "Unexpected", "Connected\nUnexpected"]
    )
    @patch("subprocess.Popen")
    def test_connect_sharepoint_online_validates_connection_result(
        self, mock_popen, connection_result
    ):
        """Only the explicit PnP connection success marker enables enrichment."""
        mock_popen.return_value = MagicMock()
        session = M365PowerShell(
            M365Credentials(),
            M365IdentityInfo(tenant_domains=["contoso.onmicrosoft.com"]),
        )
        session.execute = MagicMock(return_value="certificate_content")
        session.execute_connect = MagicMock(return_value=connection_result)

        assert session.connect_sharepoint_online("M365Global") is False
        session.close()

    @patch("subprocess.Popen")
    def test_get_sharepoint_tenant_config_projects_default_permission(self, mock_popen):
        """Tenant retrieval uses the retained PnP connection and string enums."""
        mock_popen.return_value = MagicMock()
        session = M365PowerShell(M365Credentials(), M365IdentityInfo())
        expected_result = {"DefaultLinkPermission": "View"}
        session.execute = MagicMock(return_value=expected_result)

        assert session.get_sharepoint_tenant_config() == expected_result

        command = session.execute.call_args.args[0]
        assert "Get-PnPTenant -Connection $sharePointConnection" in command
        assert "Select-Object DefaultLinkPermission" in command
        assert "ConvertTo-Json -Compress -EnumsAsStrings" in command
        assert "Get-SPOTenant" not in command
        session.close()

    @patch("subprocess.Popen")
    def test_certificate_content_is_not_logged(self, mock_popen):
        """The in-memory PFX value must never be written to logs."""
        mock_popen.return_value = MagicMock()
        certificate_content = "sensitive-base64-pfx"
        credentials = M365Credentials(
            client_id="client-id",
            tenant_id="tenant-id",
            tenant_domains=["contoso.onmicrosoft.com"],
            certificate_content=certificate_content,
        )
        with patch.object(M365PowerShell, "init_credential"):
            session = M365PowerShell(credentials, M365IdentityInfo())
        session.execute = MagicMock(return_value="")

        with (
            patch("prowler.lib.logger.logger.info") as info,
            patch("prowler.lib.logger.logger.warning") as warning,
            patch("prowler.lib.logger.logger.error") as error,
        ):
            M365PowerShell.init_credential(session, credentials)

        logged = " ".join(
            str(mock_call)
            for logger_mock in (info, warning, error)
            for mock_call in logger_mock.call_args_list
        )
        assert certificate_content not in logged
        session.execute.assert_any_call(f'$certificateBase64 = "{certificate_content}"')
        session.close()
