from unittest.mock import MagicMock, patch

from prowler.providers.m365.lib.powershell.m365_powershell import M365PowerShell
from prowler.providers.m365.models import M365Credentials


class Testm365PowerShell:
    @patch("subprocess.Popen")
    def test_init(self, mock_popen):
        mock_process = MagicMock()
        mock_popen.return_value = mock_process
        credentials = M365Credentials(user="test@example.com", passwd="test_password")

        with patch.object(M365PowerShell, "init_credential") as mock_init_credential:
            session = M365PowerShell(credentials)

            mock_popen.assert_called_once()
            mock_init_credential.assert_called_once_with(credentials)
            assert session.process == mock_process
            assert session.END == "<END>"
            session.close()

    @patch("subprocess.Popen")
    def test_sanitize(self, _):
        credentials = M365Credentials(user="test@example.com", passwd="test_password")
        session = M365PowerShell(credentials)

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
            client_id="test_client_id",
            client_secret="test_client_secret",
            tenant_id="test_tenant_id",
        )
        session = M365PowerShell(credentials)

        session.execute = MagicMock()

        session.init_credential(credentials)

        session.execute.assert_any_call(f'$user = "{credentials.user}"')
        session.execute.assert_any_call(
            f'$secureString = "{credentials.passwd}" | ConvertTo-SecureString'
        )
        session.execute.assert_any_call(
            "$credential = New-Object System.Management.Automation.PSCredential ($user, $secureString)"
        )
        session.close()

    @patch("subprocess.Popen")
    @patch("msal.ConfidentialClientApplication")
    def test_test_credentials(self, mock_msal, mock_popen):
        mock_process = MagicMock()
        mock_popen.return_value = mock_process
        mock_msal_instance = MagicMock()
        mock_msal.return_value = mock_msal_instance
        mock_msal_instance.acquire_token_by_username_password.return_value = {
            "access_token": "test_token"
        }

        credentials = M365Credentials(
            user="test@example.com",
            passwd="test_password",
            client_id="test_client_id",
            client_secret="test_client_secret",
            tenant_id="test_tenant_id",
        )
        session = M365PowerShell(credentials)

        # Mock read_output to return the decrypted password
        session.read_output = MagicMock(return_value="decrypted_password")

        # Mock execute to return the result of read_output
        session.execute = MagicMock(side_effect=lambda _: session.read_output())

        # Execute the test
        result = session.test_credentials(credentials)
        assert result is True

        # Verify execute was called with the correct commands
        session.execute.assert_any_call(
            f'$securePassword = "{credentials.passwd}" | ConvertTo-SecureString'
        )
        session.execute.assert_any_call(
            f'$credential = New-Object System.Management.Automation.PSCredential("{credentials.user}", $securePassword)\n'
        )
        session.execute.assert_any_call(
            'Write-Output "$($credential.GetNetworkCredential().Password)"'
        )

        # Verify MSAL was called with the correct parameters
        mock_msal.assert_called_once_with(
            client_id="test_client_id",
            client_credential="test_client_secret",
            authority="https://login.microsoftonline.com/test_tenant_id",
        )
        mock_msal_instance.acquire_token_by_username_password.assert_called_once_with(
            username="test@example.com",
            password="decrypted_password",
            scopes=["https://graph.microsoft.com/.default"],
        )

        session.close()

    @patch("subprocess.Popen")
    def test_remove_ansi(self, mock_popen):
        credentials = M365Credentials(user="test@example.com", passwd="test_password")
        session = M365PowerShell(credentials)

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
        session = M365PowerShell(credentials)
        command = "Get-Command"
        expected_output = {"Name": "Get-Command"}

        with patch.object(session, "execute", return_value=expected_output):
            result = session.execute(command)
            assert result == expected_output
        session.close()

    @patch("subprocess.Popen")
    def test_read_output(self, mock_popen):
        """Test the read_output method with various scenarios:
        - Normal stdout output
        - Error in stderr
        - Timeout in stdout
        - Empty output
        """
        # Setup
        mock_process = MagicMock()
        mock_popen.return_value = mock_process
        credentials = M365Credentials(user="test@example.com", passwd="test_password")
        session = M365PowerShell(credentials)

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

        # Test 4: Empty output
        mock_process.stdout.readline.side_effect = [f"{session.END}\n"]
        mock_process.stderr.readline.return_value = f"Write-Error: {session.END}\n"
        result = session.read_output()
        assert result == ""

        session.close()

    @patch("subprocess.Popen")
    def test_json_parse_output(self, mock_popen):
        mock_process = MagicMock()
        mock_popen.return_value = mock_process
        credentials = M365Credentials(user="test@example.com", passwd="test_password")
        session = M365PowerShell(credentials)

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
        session = M365PowerShell(credentials)

        session.close()

        mock_process.stdin.flush.assert_called_once()
        mock_process.terminate.assert_called_once()
