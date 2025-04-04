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

    def sanitize(self, credential: str):
        """Sanitize input to prevent command injection, allowing only letters, numbers, and @."""
        return re.sub(r"[^a-zA-Z0-9@]", "", credential)

    def init_credential(self, credentials: Microsoft365Credentials):
        # Sanitize user and password
        user = self.sanitize(credentials.user)
        passwd = self.sanitize(credentials.passwd)

        # Securely convert encrypted password to SecureString
        self.execute(f'$User = "{user}"')
        self.execute(f'$SecureString = "{passwd}" | ConvertTo-SecureString')
        self.execute(
            "$Credential = New-Object System.Management.Automation.PSCredential ($User, $SecureString)"
        )

    def test_credentials(self, credentials: Microsoft365Credentials):
        # Confirm Password
        self.process.stdin.write("$credential.GetNetworkCredential().Password" + "\n")
        self.process.stdin.write("Write-Output '<END>'\n")

        if not self.read_output():
            return False

        # Confirm User
        self.process.stdin.write(
            "Connect-MicrosoftTeams -Credential $Credential" + "\n"
        )
        self.process.stdin.write("Write-Output '<END>'\n")
        return True if credentials.user in self.read_output() else False

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

        return self.json_parse_output(self.read_output())

    def read_output(self):
        output_lines = []
        while True:
            line = self.process.stdout.readline().strip()
            line = self.remove_ansi(line)
            if line == "<END>":
                break
            output_lines.append(line)

        output = "\n".join(output_lines)

        return output

    def json_parse_output(self, output):
        """Parse comand execution to json format"""
        json_match = re.search(r"(\[.*\]|\{.*\})", output, re.DOTALL)
        if json_match:
            try:
                return json.loads(json_match.group(1))  # Return parsed JSON
            except json.JSONDecodeError:
                return {}  # Return empty output if no JSON found

    def close(self):
        """Terminate the PowerShell session"""
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
