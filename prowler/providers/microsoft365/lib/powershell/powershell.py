import json
import re
import subprocess

from prowler.providers.microsoft365.models import Microsoft365Credentials


class PowerShellSession:
    """Manages a persistent PowerShell session for executing commands."""

    def __init__(self, credentials: Microsoft365Credentials):
        """Initialize PowerShell with a persistent session."""
        self.process = subprocess.Popen(
            ["pwsh", "-NoExit", "-Command", "-"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        self.init_credential(credentials)

    def init_credential(self, credentials: Microsoft365Credentials):
        if not credentials.user or not credentials.passwd:
            print("Error: USER and PASSWORD environment variables are not set.")
            return

        # Setup credentials
        self.execute(command=f'$User = "{credentials.user}"')
        self.execute(
            f'$SecurePassword = ConvertTo-SecureString -String "{credentials.passwd}" -AsPlainText -Force'
        )
        self.execute(
            "$Credential = New-Object System.Management.Automation.PSCredential ($User, $SecurePassword)"
        )

    def remove_ansi(self, text):
        """Remove ANSI color codes from PowerShell output."""
        ansi_escape = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")

        return ansi_escape.sub("", text)

    def execute(self, command):
        """
        Sends a command to PowerShell and retrieves its output.

        :param command: PowerShell command to execute.
        """

        self.process.stdin.write(command + "\n")
        self.process.stdin.write("Write-Output '<END>'\n")
        # self.process.stdin.flush()

        output_lines = []
        while True:
            line = self.process.stdout.readline().strip()
            line = self.remove_ansi(line)
            if line == "<END>":
                break
            output_lines.append(line)

        full_output = "\n".join(output_lines)

        json_match = re.search(r"(\{.*\})", full_output, re.DOTALL)
        if json_match:
            try:
                return json.loads(json_match.group(1))  # Return parsed JSON
            except json.JSONDecodeError:
                pass  # If JSON parsing fails, return raw output

        return {}  # Return raw output if no JSON found

    def close(self):
        """Terminate the PowerShell session."""
        self.process.stdin.write("exit\n")
        self.process.stdin.flush()
        self.process.terminate()
