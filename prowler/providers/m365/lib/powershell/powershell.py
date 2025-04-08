import json
import queue
import re
import subprocess
import threading

from prowler.providers.m365.models import M365Credentials


class PowerShellSession:
    """
    Manages a persistent PowerShell session for executing Microsoft 365-related commands.

    This class encapsulates the lifecycle and command execution of a persistent PowerShell
    subprocess. It supports Microsoft 365 authentication using credentials provided through
    the `M365Credentials` model and provides methods to interact with PowerShell modules.

    Features:
    - Maintains a persistent PowerShell session.
    - Initializes and manages PowerShell credential objects securely.
    - Sanitizes credentials to prevent command injection.
    - Executes PowerShell commands and handles JSON-formatted responses.

    Attributes
    ----------
    END : str
        Marker string used to signal the end of PowerShell command output.
    process : subprocess.Popen
        The underlying PowerShell subprocess with open stdin, stdout, and stderr streams.

    Parameters
    ----------
    credentials : M365Credentials
        A credentials object containing username and password for Microsoft 365 authentication.

    Examples
    --------
    >>> credentials = M365Credentials(user="your_email@example.com", passwd="6500780061006d0070006c006500700061007300730077006f0072006400")
    >>> session = PowerShellSession(credentials)
    >>> session.get_teams_settings()
    {'AllowEmailIntoChannel': True, ...}
    >>> session.close()
    """

    END = "<END>"

    def __init__(self, credentials: M365Credentials):
        """
        Initialize a persistent PowerShell session.

        Creates a subprocess running PowerShell with pipes for stdin, stdout, and stderr.
        Initializes credential objects for Microsoft 365 authentication.

        Args:
            credentials (M365Credentials): The credentials object containing
                username and encrypted password for Microsoft 365 authentication.
        """
        self.process = subprocess.Popen(
            ["pwsh", "-NoExit", "-Command", "-"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        self.init_credential(credentials)

    def sanitize(self, credential: str):
        """
        Sanitize input to prevent command injection.

        Filters the input string to allow only letters, numbers, @, periods, underscores,
        plus signs, and hyphens.

        Args:
            credential (str): The string to sanitize.

        Returns:
            str: The sanitized string.
        """
        return re.sub(r"[^a-zA-Z0-9@._+\-]", "", credential)

    def init_credential(self, credentials: M365Credentials):
        """
        Initialize PowerShell credential object for authentication.

        Sanitizes the username and password, then creates a PSCredential object
        in the PowerShell session for use with Microsoft 365 cmdlets.

        Args:
            credentials (M365Credentials): The credentials object containing
                username and password.
        """
        # Sanitize user and password
        user = self.sanitize(credentials.user)
        passwd = self.sanitize(credentials.passwd)

        # Securely convert encrypted password to SecureString
        self.execute(f'$User = "{user}"')
        self.execute(f'$SecureString = "{passwd}" | ConvertTo-SecureString')
        self.execute(
            "$Credential = New-Object System.Management.Automation.PSCredential ($User, $SecureString)"
        )

    def test_credentials(self, credentials: M365Credentials):
        """
        Test Microsoft 365 credentials by attempting to connect to Microsoft Teams.

        This method validates the provided credentials by:
        1. Confirming the password is valid by retrieving it from the credential object
        2. Attempting to connect to Microsoft Teams using the credentials

        Args:
            credentials (M365Credentials): The credentials object containing
                username and password to test

        Returns:
            bool: True if credentials are valid and connection succeeds, False otherwise.
                Specifically returns True if the username appears in the connection output,
                indicating successful authentication.

        Note:
            This method uses PowerShell commands to test the credentials and relies on
            the PowerShell Microsoft Teams module being installed and available.
        """
        # Confirm Password
        self.process.stdin.write("$credential.GetNetworkCredential().Password\n")
        self.process.stdin.write(f"Write-Output '{self.END}'\n")

        if not self.read_output():
            return False

        # Confirm User
        self.process.stdin.write("Connect-MicrosoftTeams -Credential $Credential\n")
        self.process.stdin.write(f"Write-Output '{self.END}'\n")
        return credentials.user in self.read_output()

    def remove_ansi(self, text):
        """
        Remove ANSI color codes and other escape sequences from PowerShell output.

        PowerShell often includes ANSI escape sequences in its output for terminal
        coloring and formatting. This method strips these sequences to produce clean,
        parseable text that can be processed programmatically.

        The method uses a regular expression pattern that matches the full range of ANSI escape sequences.

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

    def execute(self, command):
        """
        Send a command to PowerShell and retrieve its output.

        Executes the given command in the PowerShell session, adds an END marker,
        and parses the output as JSON if possible.

        Args:
            command (str): PowerShell command to execute.

        Returns:
            dict: JSON-parsed output if available, otherwise an empty dictionary.
        """

        self.process.stdin.write(f"{command}\n")
        self.process.stdin.write(f"Write-Output '{self.END}'\n")

        return self.json_parse_output(self.read_output())

    def read_output(self, timeout=10, default=""):
        """
        Read output from a process with timeout functionality.

        This method reads lines from process stdout until it encounters the END marker
        or the stream ends. If reading takes longer than the timeout period, the method
        returns a default value while allowing the reading to continue in the background.

        Args:
            timeout (int, optional): Maximum time in seconds to wait for output. Defaults to 5.
            default (str, optional): Value to return if timeout occurs. Defaults to empty string.

        Returns:
            str: Concatenated output lines or default value if timeout occurs.
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

        # Start the reader thread
        thread = threading.Thread(target=reader_thread)
        thread.daemon = True  # Thread will terminate when main program exits
        thread.start()

        try:
            return result_queue.get(timeout=timeout)
        except queue.Empty:
            return default

    def json_parse_output(self, output):
        """
        Parse command execution output to JSON format.

        Searches for a JSON object in the output string and parses it.

        Args:
            output (str): The string output from a PowerShell command.

        Returns:
            dict: Parsed JSON object if found, otherwise an empty dictionary.
        """
        json_match = re.search(r"(\[.*\]|\{.*\})", output, re.DOTALL)

        if json_match:
            return json.loads(
                json_match.group(1)
            )  # Return parsed JSON (It'll be always be one)

        return {}  # Return empty output if no JSON found

    def close(self):
        """
        Terminate the PowerShell session.

        Sends an exit command to PowerShell and terminates the subprocess.
        """
        self.process.stdin.write("exit\n")
        self.process.stdin.flush()
        self.process.terminate()

    def connect_microsoft_teams(self):
        """Connect to Microsoft Teams Module PowerShell Module"""
        return self.execute("Connect-MicrosoftTeams -Credential $Credential")

    def get_teams_settings(self):
        """Get Teams Client Settings"""
        return self.execute("Get-CsTeamsClientConfiguration | ConvertTo-Json")

    def connect_exchange_online(self):
        """Connect to Exchange Online PowerShell Module"""
        return self.execute("Connect-ExchangeOnline -Credential $Credential")

    def get_audit_log_config(self):
        """Get Purview Admin Audit Log Settings"""
        return self.execute(
            "Get-AdminAuditLogConfig | Select-Object UnifiedAuditLogIngestionEnabled | ConvertTo-Json"
        )
