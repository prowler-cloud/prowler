from unittest.mock import MagicMock, patch

from prowler.providers.m365.lib.powershell.m365_powershell import PowerShellSession


class TestPowerShellSession:
    @patch("subprocess.Popen")
    def test_init(self, mock_popen):
        mock_process = MagicMock()
        mock_popen.return_value = mock_process
        session = PowerShellSession()

        mock_popen.assert_called_once()
        assert session.process == mock_process
        assert session.END == "<END>"

    @patch("subprocess.Popen")
    def test_sanitize(self, _):
        session = PowerShellSession()

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

    @patch("subprocess.Popen")
    def test_remove_ansi(self, text):
        session = PowerShellSession()

        test_cases = [
            ("\x1b[32mSuccess\x1b[0m", "Success"),
            ("\x1b[31mError\x1b[0m", "Error"),
            ("\x1b[33mWarning\x1b[0m", "Warning"),
            ("Normal text", "Normal text"),
            ("\x1b[1mBold\x1b[0m", "Bold"),
        ]

        for input_str, expected in test_cases:
            assert session.remove_ansi(input_str) == expected

    @patch("subprocess.Popen")
    def test_execute(self, mock_popen):
        mock_process = MagicMock()
        mock_popen.return_value = mock_process
        session = PowerShellSession()
        command = "Get-Command"
        expected_output = '{"Name": "Get-Command"}'

        with patch.object(session, "read_output", return_value=expected_output):
            result = session.execute(command)

            mock_process.stdin.write.assert_any_call(f"{command}\n")
            mock_process.stdin.write.assert_any_call(f"Write-Output '{session.END}'\n")
            assert result == {"Name": "Get-Command"}

    @patch("subprocess.Popen")
    def test_read_output(self, mock_popen):
        mock_process = MagicMock()
        mock_popen.return_value = mock_process
        session = PowerShellSession()

        # Test normal output
        with patch.object(session, "read_output", return_value="test@example.com"):
            assert session.read_output() == "test@example.com"

        # Test timeout
        mock_process.stdout.readline.return_value = "test output\n"
        with patch.object(session, "remove_ansi", return_value="test output"):
            assert session.read_output(timeout=0.1, default="") == ""

    @patch("subprocess.Popen")
    def test_json_parse_output(self, mock_popen):
        mock_process = MagicMock()
        mock_popen.return_value = mock_process
        session = PowerShellSession()

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

    @patch("subprocess.Popen")
    def test_close(self, mock_popen):
        mock_process = MagicMock()
        mock_popen.return_value = mock_process
        session = PowerShellSession()

        session.close()

        mock_process.stdin.flush.assert_called_once()
        mock_process.terminate.assert_called_once()
