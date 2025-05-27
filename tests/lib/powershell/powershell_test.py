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
        session.close()

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
        session.close()

    @patch("subprocess.Popen")
    def test_remove_ansi(self, mock_popen):
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
        session.close()

    @patch("subprocess.Popen")
    def test_execute(self, mock_popen):
        """Test the execute method with various scenarios:
        - Normal command execution
        - JSON parsing enabled
        - Timeout handling
        - Error handling
        """
        # Setup
        mock_process = MagicMock()
        mock_popen.return_value = mock_process
        session = PowerShellSession()

        # Test 1: Normal command execution
        mock_process.stdout.readline.side_effect = ["Hello World\n", f"{session.END}\n"]
        mock_process.stderr.readline.return_value = f"Write-Error: {session.END}\n"
        with patch.object(session, "remove_ansi", side_effect=lambda x: x):
            result = session.execute("Get-Command")
            assert result == "Hello World"
            mock_process.stdin.write.assert_any_call("Get-Command\n")
            mock_process.stdin.write.assert_any_call(f"Write-Output '{session.END}'\n")
            mock_process.stdin.write.assert_any_call(f"Write-Error '{session.END}'\n")

        # Test 2: JSON parsing enabled
        mock_process.stdout.readline.side_effect = [
            '{"key": "value"}\n',
            f"{session.END}\n",
        ]
        mock_process.stderr.readline.return_value = f"Write-Error: {session.END}\n"
        with patch.object(session, "remove_ansi", side_effect=lambda x: x):
            with patch.object(
                session, "json_parse_output", return_value={"key": "value"}
            ) as mock_json_parse:
                result = session.execute("Get-Command", json_parse=True)
                assert result == {"key": "value"}
                mock_json_parse.assert_called_once_with('{"key": "value"}')

        # Test 3: Timeout handling
        mock_process.stdout.readline.side_effect = ["test output\n"]  # No END marker
        mock_process.stderr.readline.return_value = f"Write-Error: {session.END}\n"
        result = session.execute("Get-Command", timeout=0.1)
        assert result == ""

        # Test 4: Error handling
        mock_process.stdout.readline.side_effect = ["\n", f"{session.END}\n"]
        mock_process.stderr.readline.side_effect = [
            "Write-Error: This is an error\n",
            f"Write-Error: {session.END}\n",
        ]
        with patch.object(session, "remove_ansi", side_effect=lambda x: x):
            with patch("prowler.lib.logger.logger.error") as mock_error:
                result = session.execute("Get-Command")
                assert result == ""
                mock_error.assert_called_once_with(
                    "PowerShell error output: Write-Error: This is an error"
                )

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
        session = PowerShellSession()

        # Test 1: Normal stdout output
        mock_process.stdout.readline.side_effect = ["Hello World\n", f"{session.END}\n"]
        mock_process.stderr.readline.return_value = f"Write-Error: {session.END}\n"
        with patch.object(session, "remove_ansi", side_effect=lambda x: x):
            result = session.read_output()
            assert result == "Hello World"

        # Test 2: Error in stderr
        mock_process.stdout.readline.side_effect = ["\n", f"{session.END}\n"]
        mock_process.stderr.readline.side_effect = [
            "Write-Error: This is an error\n",
            f"Write-Error: {session.END}\n",
        ]
        with patch.object(session, "remove_ansi", side_effect=lambda x: x):
            with patch("prowler.lib.logger.logger.error") as mock_error:
                result = session.read_output()
                assert result == ""
                mock_error.assert_called_once_with(
                    "PowerShell error output: Write-Error: This is an error"
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
        session.close()

    @patch("subprocess.Popen")
    def test_json_parse_output_logging(self, mock_popen):
        mock_process = MagicMock()
        mock_popen.return_value = mock_process
        session = PowerShellSession()

        # Test warning for non-JSON output
        with patch("prowler.lib.logger.logger.error") as mock_error:
            result = session.json_parse_output("some text without json")
            assert result == {}
            mock_error.assert_called_once_with(
                "Unexpected PowerShell output: some text without json\n"
            )

        session.close()

    @patch("subprocess.Popen")
    def test_json_parse_output_with_text_around_json(self, mock_popen):
        mock_process = MagicMock()
        mock_popen.return_value = mock_process
        session = PowerShellSession()

        # Test JSON extraction from text with surrounding content
        result = session.json_parse_output('some text {"key": "value"} more text')
        assert result == {"key": "value"}

        result = session.json_parse_output('prefix [{"key": "value"}] suffix')
        assert result == [{"key": "value"}]

        # Test non-JSON text returns empty dict
        result = session.json_parse_output("just some text")
        assert result == {}

        session.close()

    @patch("subprocess.Popen")
    def test_json_parse_output_empty(self, mock_popen):
        mock_process = MagicMock()
        mock_popen.return_value = mock_process
        session = PowerShellSession()

        # Test empty string
        result = session.json_parse_output("")
        assert result == {}

        session.close()

    @patch("subprocess.Popen")
    def test_close(self, mock_popen):
        mock_process = MagicMock()
        mock_popen.return_value = mock_process
        session = PowerShellSession()

        session.close()

        mock_process.stdin.flush.assert_called_once()
        mock_process.terminate.assert_called_once()
        mock_process = None
