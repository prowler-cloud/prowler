import json
import platform
import queue
import re
import subprocess
import threading


class PowerShellSession:
    """
    Base class for managing PowerShell sessions.

    This class provides the core functionality for interacting with PowerShell,
    including command execution, output handling, and session management.
    It serves as a foundation for more specific PowerShell implementations.

    Features:
    - Maintains a persistent PowerShell session
    - Handles command execution and output parsing
    - Provides secure input sanitization
    - Manages ANSI escape sequence removal
    - Supports JSON output parsing
    - Implements timeout handling for long-running commands

    Attributes:
        END (str): Marker string used to signal the end of PowerShell command output.
        process (subprocess.Popen): The underlying PowerShell subprocess with open stdin, stdout, and stderr streams.

    Note:
        This is an abstract base class that should be extended by specific implementations
        for different PowerShell use cases.
    """

    END = "<END>"

    def __init__(self):
        """
        Initialize a persistent PowerShell session.

        Creates a subprocess running PowerShell with pipes for stdin, stdout, and stderr.
        The session is configured to run in interactive mode with no exit.

        Note:
            This is a base implementation that should be extended by subclasses
            to add specific initialization logic (e.g., credential setup).
        """
        # Determine the appropriate PowerShell command based on the OS
        if platform.system() == "Windows":
            powershell_cmd = "powershell"
        else:
            powershell_cmd = "pwsh"

        self.process = subprocess.Popen(
            [powershell_cmd, "-NoExit", "-Command", "-"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )

    def sanitize(self, credential: str) -> str:
        """
        Sanitize input to prevent command injection.

        Filters the input string to allow only letters, numbers, @, periods, underscores,
        plus signs, and hyphens. This is a security measure to prevent command injection
        attacks through credential input.

        Args:
            credential (str): The string to sanitize.

        Returns:
            str: The sanitized string containing only allowed characters.

        Example:
            >>> sanitize("user@domain.com!@#$")
            "user@domain.com"
        """
        return re.sub(r"[^a-zA-Z0-9@._+\-]", "", credential)

    def remove_ansi(self, text: str) -> str:
        """
        Remove ANSI color codes and other escape sequences from PowerShell output.

        PowerShell often includes ANSI escape sequences in its output for terminal
        coloring and formatting. This method strips these sequences to produce clean,
        parseable text that can be processed programmatically.

        Args:
            text (str): Raw text containing ANSI escape sequences from PowerShell output.

        Returns:
            str: Clean text with all ANSI escape sequences removed, suitable for parsing.

        Example:
            >>> remove_ansi("\x1b[32mSuccess\x1b[0m")
            "Success"
        """
        ansi_escape = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
        return ansi_escape.sub("", text)

    def execute(self, command: str) -> dict:
        """
        Send a command to PowerShell and retrieve its output.

        Executes the given command in the PowerShell session, adds an END marker,
        and parses the output as JSON if possible. The command is executed
        asynchronously with a timeout mechanism.

        Args:
            command (str): PowerShell command to execute.

        Returns:
            dict: JSON-parsed output if available, otherwise an empty dictionary.

        Example:
            >>> execute("Get-Process | ConvertTo-Json")
            {"Name": "process1", "Id": 1234}
        """
        self.process.stdin.write(f"{command}\n")
        self.process.stdin.write(f"Write-Output '{self.END}'\n")
        return self.json_parse_output(self.read_output())

    def read_output(self, timeout: int = 10, default: str = "") -> str:
        """
        Read output from a process with timeout functionality.

        This method reads lines from process stdout until it encounters the END marker
        or the stream ends. If reading takes longer than the timeout period, the method
        returns a default value while allowing the reading to continue in the background.

        Args:
            timeout (int, optional): Maximum time in seconds to wait for output.
                Defaults to 10.
            default (str, optional): Value to return if timeout occurs.
                Defaults to empty string.

        Returns:
            str: Concatenated output lines or default value if timeout occurs.

        Note:
            This method uses a daemon thread to read the output asynchronously,
            ensuring that the main thread is not blocked.
        """
        output_lines = []
        result_queue = queue.Queue()

        def reader_thread():
            try:
                while True:
                    line = self.remove_ansi(self.process.stdout.readline().strip())
                    if line == self.END:
                        break
                    output_lines.append(line)
                result_queue.put("\n".join(output_lines))
            except Exception as e:
                result_queue.put(str(e))

        thread = threading.Thread(target=reader_thread)
        thread.daemon = True
        thread.start()

        try:
            return result_queue.get(timeout=timeout)
        except queue.Empty:
            return default

    def json_parse_output(self, output: str) -> dict:
        """
        Parse command execution output to JSON format.

        Searches for a JSON object in the output string and parses it.
        The method looks for both object and array JSON structures.

        Args:
            output (str): The string output from a PowerShell command.

        Returns:
            dict: Parsed JSON object if found, otherwise an empty dictionary.

        Example:
            >>> json_parse_output('Some text {"key": "value"} more text')
            {"key": "value"}
        """
        json_match = re.search(r"(\[.*\]|\{.*\})", output, re.DOTALL)
        if json_match:
            return json.loads(json_match.group(1))
        return {}

    def close(self) -> None:
        """
        Terminate the PowerShell session.

        Sends an exit command to PowerShell and terminates the subprocess.
        This method should be called when the session is no longer needed
        to ensure proper cleanup of resources.

        Note:
            It's important to call this method when done with the session
            to prevent resource leaks.
        """
        self.process.stdin.write("exit\n")
        self.process.stdin.flush()
        self.process.terminate()
