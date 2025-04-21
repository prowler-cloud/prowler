from unittest.mock import MagicMock, patch

import pytest

from prowler.providers.m365.exceptions.exceptions import (
    M365UserNotBelongingToTenantError,
)
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
            user="test@contoso.onmicrosoft.com",
            passwd="test_password",
            client_id="test_client_id",
            client_secret="test_client_secret",
            tenant_id="test_tenant_id",
            provider_id="contoso.onmicrosoft.com",
        )
        session = M365PowerShell(credentials)

        session.execute = MagicMock()
        session.process.stdin.write = MagicMock()
        session.read_output = MagicMock(return_value="decrypted_password")

        assert session.test_credentials(credentials) is True

        session.execute.assert_any_call(
            f'$securePassword = "{credentials.passwd}" | ConvertTo-SecureString\n'
        )
        session.execute.assert_any_call(
            f'$credential = New-Object System.Management.Automation.PSCredential("{credentials.user}", $securePassword)\n'
        )
        session.process.stdin.write.assert_any_call(
            'Write-Output "$($credential.GetNetworkCredential().Password)"\n'
        )
        session.process.stdin.write.assert_any_call(f"Write-Output '{session.END}'\n")

        mock_msal.assert_called_once_with(
            client_id="test_client_id",
            client_credential="test_client_secret",
            authority="https://login.microsoftonline.com/test_tenant_id",
        )
        mock_msal_instance.acquire_token_by_username_password.assert_called_once_with(
            username="test@contoso.onmicrosoft.com",
            password="decrypted_password",
            scopes=["https://graph.microsoft.com/.default"],
        )
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
            provider_id="contoso.onmicrosoft.com",
        )
        session = M365PowerShell(credentials)

        session.execute = MagicMock()
        session.process.stdin.write = MagicMock()
        session.read_output = MagicMock(return_value="decrypted_password")

        with pytest.raises(M365UserNotBelongingToTenantError) as exception:
            session.test_credentials(credentials)

        assert exception.type == M365UserNotBelongingToTenantError
        assert "The provided M365 User does not belong to the specified tenant." in str(
            exception.value
        )

        mock_msal.assert_called_once_with(
            client_id="test_client_id",
            client_credential="test_client_secret",
            authority="https://login.microsoftonline.com/test_tenant_id",
        )
        mock_msal_instance.acquire_token_by_username_password.assert_called_once_with(
            username="user@otherdomain.com",
            password="decrypted_password",
            scopes=["https://graph.microsoft.com/.default"],
        )
        session.close()

    @patch("subprocess.Popen")
    @patch("msal.ConfidentialClientApplication")
    def test_test_credentials_auth_failure(self, mock_msal, mock_popen):
        mock_process = MagicMock()
        mock_popen.return_value = mock_process
        mock_msal_instance = MagicMock()
        mock_msal.return_value = mock_msal_instance
        mock_msal_instance.acquire_token_by_username_password.return_value = None

        credentials = M365Credentials(
            user="test@contoso.onmicrosoft.com",
            passwd="test_password",
            client_id="test_client_id",
            client_secret="test_client_secret",
            tenant_id="test_tenant_id",
            provider_id="contoso.onmicrosoft.com",
        )
        session = M365PowerShell(credentials)

        session.execute = MagicMock()
        session.process.stdin.write = MagicMock()
        session.read_output = MagicMock(return_value="decrypted_password")

        assert session.test_credentials(credentials) is False

        mock_msal.assert_called_once_with(
            client_id="test_client_id",
            client_credential="test_client_secret",
            authority="https://login.microsoftonline.com/test_tenant_id",
        )
        mock_msal_instance.acquire_token_by_username_password.assert_called_once_with(
            username="test@contoso.onmicrosoft.com",
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
        expected_output = '{"Name": "Get-Command"}'

        with patch.object(session, "read_output", return_value=expected_output):
            result = session.execute(command)

            mock_process.stdin.write.assert_any_call(f"{command}\n")
            mock_process.stdin.write.assert_any_call(f"Write-Output '{session.END}'\n")
            assert result == {"Name": "Get-Command"}
        session.close()

    @patch("subprocess.Popen")
    def test_read_output(self, mock_popen):
        mock_process = MagicMock()
        mock_popen.return_value = mock_process
        credentials = M365Credentials(user="test@example.com", passwd="test_password")
        session = M365PowerShell(credentials)

        # Test normal output
        with patch.object(session, "read_output", return_value="test@example.com"):
            assert session.read_output() == "test@example.com"

        # Test timeout
        mock_process.stdout.readline.return_value = "test output\n"
        with patch.object(session, "remove_ansi", return_value="test output"):
            assert session.read_output(timeout=0.1, default="") == ""
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
