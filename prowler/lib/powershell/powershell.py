import json
import platform
import queue
import re
import select
import subprocess
import threading
import time

from prowler.lib.logger import logger


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

    def execute(self, command: str, json_parse: bool = False) -> str | dict:
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
        return (
            self.json_parse_output(self.read_output())
            if json_parse
            else self.read_output()
        )

    def read_output(self, timeout: int = 10, default: str = "") -> str:
        """
        Read output from a process with timeout functionality.

        This method reads lines from process stdout and stderr until it encounters the END marker
        or the stream ends. If reading takes longer than the timeout period, the method
        returns a default value while allowing the reading to continue in the background.

        Args:
            timeout (int, optional): Maximum time in seconds to wait for output.
                Defaults to 10.
            default (str, optional): Value to return if timeout occurs.
                Defaults to empty string.

        Returns:
            str: Error message if errors are present, otherwise normal output.

        Note:
            This method uses a daemon thread to read the output asynchronously,
            ensuring that the main thread is not blocked.
        """
        output_lines = []
        error_lines = []
        result_queue = queue.Queue()
        error_queue = queue.Queue()
        thread_completed = threading.Event()

        def reader_thread():
            try:
                # First, read stdout until END marker
                while True:
                    rlist, _, _ = select.select([self.process.stdout], [], [], 0.1)
                    if rlist:
                        line = self.remove_ansi(self.process.stdout.readline().strip())
                        if line == self.END:
                            break
                        if line:
                            output_lines.append(line)

                # Then, read stderr for a short time
                stderr_timeout = 1.0
                start_time = time.time()
                while time.time() - start_time < stderr_timeout:
                    rlist, _, _ = select.select([self.process.stderr], [], [], 0.1)
                    if rlist:
                        line = self.remove_ansi(self.process.stderr.readline().strip())
                        if line:
                            error_lines.append(line)
                    else:
                        break

                # Put results in appropriate queues
                if error_lines:
                    error_queue.put("\n".join(error_lines))
                else:
                    result_queue.put("\n".join(output_lines))
            except Exception as error:
                error_queue.put(str(error))
            finally:
                thread_completed.set()

        thread = threading.Thread(target=reader_thread)
        thread.daemon = True
        thread.start()

        # Wait for thread to complete or timeout
        thread_completed.wait(timeout=timeout)

        # Check for errors first
        if not error_queue.empty():
            return error_queue.get(timeout=0)

        # If no errors, return normal output
        try:
            return result_queue.get(timeout=0)
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

        Raises:
            JSONDecodeError: If the JSON parsing fails.

        Example:
            >>> json_parse_output('Some text {"key": "value"} more text')
            {"key": "value"}
        """
        if output == "":
            return {}

        json_match = re.search(r"(\[.*\]|\{.*\})", output, re.DOTALL)
        if not json_match:
            logger.error(
                f"Unexpected PowerShell output: {output}\n",
            )
        else:
            try:
                return json.loads(json_match.group(1))
            except json.JSONDecodeError as error:
                logger.error(
                    f"Error parsing PowerShell output as JSON: {str(error)}\n",
                )

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
        if self.process:
            try:
                # Send exit command
                self.process.stdin.write("exit\n")
                self.process.stdin.flush()

                # Terminate the process
                self.process.terminate()

                # Wait for the process to finish
                self.process.wait(timeout=5)
            except Exception:
                # If process is still running, force kill it
                self.process.kill()
            finally:
                # Close all pipes
                self.process.stdin.close()
                self.process.stdout.close()
                self.process.stderr.close()
                self.process = None
