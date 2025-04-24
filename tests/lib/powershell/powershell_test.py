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
        mock_process = MagicMock()
        mock_popen.return_value = mock_process
        session = PowerShellSession()
        command = "Get-Command"
        expected_output = '{"Name": "Get-Command"}'

        with patch.object(session, "read_output", return_value=expected_output):
            with patch.object(
                session, "json_parse_output", return_value={"Name": "Get-Command"}
            ):
                result = session.execute(command, json_parse=True)

                mock_process.stdin.write.assert_any_call(f"{command}\n")
                mock_process.stdin.write.assert_any_call(
                    f"Write-Output '{session.END}'\n"
                )
                assert result == {"Name": "Get-Command"}
        session.close()

    @patch("subprocess.Popen")
    def test_read_output(self, mock_popen):
        mock_process = MagicMock()
        mock_popen.return_value = mock_process

        # Mock fileno() for stdout and stderr
        mock_process.stdout.fileno.return_value = 1
        mock_process.stderr.fileno.return_value = 2

        session = PowerShellSession()

        # Test normal output with Write-Output
        mock_process.stdout.readline.side_effect = ["Hello World\n", f"{session.END}\n"]
        mock_process.stderr.readline.return_value = ""
        with patch("select.select", return_value=([mock_process.stdout], [], [])):
            with patch.object(session, "remove_ansi", side_effect=lambda x: x):
                result = session.read_output()
                assert result == "Hello World"

        # Test error output with Write-Error
        mock_process.stdout.readline.side_effect = ["\n", f"{session.END}\n"]
        mock_process.stderr.readline.side_effect = [
            "Write-Error: This is an error\n",
            "",
        ]
        with patch(
            "select.select",
            side_effect=[
                (
                    [mock_process.stdout],
                    [],
                    [],
                ),  # First select: stdout ready (empty line)
                ([mock_process.stdout], [], []),  # Second select: stdout ready (END)
                ([mock_process.stderr], [], []),  # Third select: stderr ready (error)
                ([], [], []),  # Fourth select: nothing ready (end loop)
            ],
        ):
            with patch.object(session, "remove_ansi", side_effect=lambda x: x):
                result = session.read_output()
                assert result == "Write-Error: This is an error"

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
        with patch("prowler.lib.logger.logger.warning") as mock_warning:
            result = session.json_parse_output("some text without json")
            assert result == {}
            mock_warning.assert_called_once_with(
                "Could not parse PowerShell output as JSON.\nOriginal output: some text without json"
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
