import json
import re
import subprocess

from msal import ConfidentialClientApplication
from msgraph import GraphServiceClient

from prowler.lib.logger import logger
from prowler.providers.microsoft365.microsoft365_provider import Microsoft365Provider


class Microsoft365Service:
    def __init__(
        self,
        provider: Microsoft365Provider,
    ):
        self.client = GraphServiceClient(credentials=provider.session)
        self.identity = provider.identity
        self.credentials = provider.session.credentials[0]._credential
        self.powershell = subprocess.Popen(
            ["pwsh", "-NoExit", "-Command", "-"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.audit_config = provider.audit_config
        self.fixer_config = provider.fixer_config

        app = ConfidentialClientApplication(
            client_id=self.credentials._client_id,
            authority=f"https://login.microsoftonline.com/{self.identity.tenant_id}",
            client_credential=self.credentials._client_credential,
        )
        self.token = app.acquire_token_for_client(
            scopes=["https://graph.microsoft.com/.default"]
        )

    def connect_service(self, cmd: str):
        # Connect to Microsoft Service
        self.execute(cmd)

    def execute(self, cmd: str):
        # Execute command in PowerShell
        self.powershell.stdin.write(cmd + "\n")
        self.powershell.stdin.flush()
        # stdout, stderr = self.powershell.communicate()
        # Read output without closing the process

        if "Connect" in cmd:
            return ""

        output_lines = []
        while True:
            line = self.powershell.stdout.readline()
            if not line:
                break
            output_lines.append(line)
            if "}" in line:
                break
        stdout = "".join(output_lines)

        # Extract only the JSON response
        json_match = re.search(r"(\{.*\})", stdout, re.DOTALL)
        if not json_match:
            logger.warning("Failed to extract JSON")
            return ""

        response = json.loads(json_match.group(1))

        return response
