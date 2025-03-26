import json
import os
import re
import subprocess


class PowerShellSession:
    """Manages a persistent PowerShell session for executing commands."""

    def __init__(self):
        """Initialize PowerShell with a persistent session."""
        self.process = subprocess.Popen(
            ["pwsh", "-NoExit", "-Command", "-"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
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

        return full_output

        # Extract JSON from output if present
        json_match = re.search(r"(\{.*\})", full_output, re.DOTALL)
        if json_match:
            try:
                return json.loads(json_match.group(1))  # Return parsed JSON
            except json.JSONDecodeError:
                pass  # If JSON parsing fails, return raw output

        return "full_output"  # Return raw output if no JSON found

    def close(self):
        """Terminate the PowerShell session."""
        self.process.stdin.write("exit\n")
        self.process.stdin.flush()
        self.process.terminate()


def main():
    """Main function to authenticate and fetch Microsoft Teams configuration."""

    # Get credentials from environment variables
    username = os.getenv("USER")
    password = os.getenv("PASSWORD")

    if not username or not password:
        print("Error: USER and PASSWORD environment variables are not set.")
        return

    # Start PowerShell session
    ps_session = PowerShellSession()

    # Setup credentials
    ps_session.execute(command=f'$User = "{username}"')
    ps_session.execute(
        f'$SecurePassword = ConvertTo-SecureString -String "{password}" -AsPlainText -Force'
    )
    ps_session.execute(
        "$Credential = New-Object System.Management.Automation.PSCredential ($User, $SecurePassword)"
    )

    # Connect to Microsoft Teams
    ps_session.execute("Connect-MicrosoftTeams -Credential $Credential")

    # Get Microsoft Teams configuration
    json_response = ps_session.execute(
        "Get-CsTeamsClientConfiguration | ConvertTo-Json"
    )

    # Extract JSON
    json_match = re.search(r"(\{.*\})", json_response, re.DOTALL)
    if not json_match:
        print("Error: Failed to extract JSON")
    try:
        response = json.loads(json_match.group(1))
    except json.JSONDecodeError as e:
        print("JSON decoding error:", e)
        response = {}

    print(json.dumps(response, indent=4))

    # Validate configuration
    if all(
        response.get(key, True) is False
        for key in [
            "AllowDropBox",
            "AllowBox",
            "AllowGoogleDrive",
            "AllowShareFile",
            "AllowEgnyte",
        ]
    ):
        print("PASS")
    else:
        print("FAIL")

    # Close PowerShell session
    ps_session.close()


if __name__ == "__main__":
    main()
