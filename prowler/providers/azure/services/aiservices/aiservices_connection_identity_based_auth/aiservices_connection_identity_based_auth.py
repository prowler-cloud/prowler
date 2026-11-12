from typing import Optional

from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.aiservices.aiservices_client import (
    aiservices_client,
)

# A credential stored in the connection. Every agent and every caller that can
# use the connection presents the same secret, so the target cannot tell them
# apart and the secret does not expire on its own.
STATIC_SECRET_AUTH_TYPES = {
    "accesskey",
    "accountkey",
    "apikey",
    "customkeys",
    "pat",
    "sas",
    "usernamepassword",
}

# The caller authenticates as a directory principal, so the target sees who
# called and the credential is issued and expires per request.
IDENTITY_AUTH_TYPES = {
    "aad",
    "agenticidentity",
    "agenticidentitytoken",
    "managedidentity",
    "oauth2",
    "projectmanagedidentity",
    "serviceprincipal",
}

NO_AUTH_TYPES = {"none", ""}


class aiservices_connection_identity_based_auth(Check):
    """AI services connections authenticate with an identity, not a stored key."""

    @staticmethod
    def _scope(account_name: str, project_name: Optional[str] = None) -> str:
        """Name the place a connection is held, as a finding reads it.

        Args:
            account_name: The AI services account.
            project_name: The project holding the connection, or `None` and
                `""` for a connection held by the account itself.

        Returns:
            The scope, ready to put in a finding's text.
        """
        if project_name:
            return f"project {project_name} of AI services account {account_name}"
        return f"AI services account {account_name}"

    def execute(self) -> list[Check_Report_Azure]:
        """Evaluate the authentication type of every connection.

        One finding per connection. A connection whose authentication type is
        not one this check knows is reported MANUAL rather than guessed at:
        the service accepts values that are not in the SDK enum, and treating
        an unrecognised one as safe or unsafe would be made up.

        Returns:
            One finding per connection, plus one per scope whose connections
            could not be listed: a whole account, or a single project of one.
        """
        findings = []
        for subscription_id, accounts in aiservices_client.accounts.items():
            subscription_name = aiservices_client.subscriptions.get(
                subscription_id, subscription_id
            )
            for account in accounts.values():
                if account.connections is None:
                    report = Check_Report_Azure(
                        metadata=self.metadata(), resource=account
                    )
                    report.subscription = subscription_id
                    report.location = account.location
                    report.status = "MANUAL"
                    report.status_extended = (
                        f"Connections of AI services account {account.name} from "
                        f"subscription {subscription_name} ({subscription_id}) "
                        f"could not be listed, so their authentication type is "
                        f"unknown."
                    )
                    findings.append(report)
                    continue

                # A scope that could not be read is reported, so its
                # connections are not mistaken for connections that are absent.
                for project_name in account.unlisted_connection_scopes:
                    report = Check_Report_Azure(
                        metadata=self.metadata(), resource=account
                    )
                    report.subscription = subscription_id
                    report.location = account.location
                    report.status = "MANUAL"
                    report.status_extended = (
                        f"Connections of "
                        f"{self._scope(account.name, project_name)} from "
                        f"subscription {subscription_name} ({subscription_id}) "
                        f"could not be listed, so their authentication type is "
                        f"unknown."
                    )
                    findings.append(report)

                for connection in account.connections:
                    report = Check_Report_Azure(
                        metadata=self.metadata(), resource=connection
                    )
                    report.subscription = subscription_id
                    report.location = account.location
                    scope = self._scope(account.name, connection.project_name)
                    prefix = (
                        f"Connection {connection.name} in {scope} from subscription "
                        f"{subscription_name} ({subscription_id})"
                    )
                    auth = connection.auth_type.lower()
                    if auth in IDENTITY_AUTH_TYPES:
                        report.status = "PASS"
                        report.status_extended = (
                            f"{prefix} authenticates with the identity type "
                            f"{connection.auth_type}."
                        )
                    elif auth in STATIC_SECRET_AUTH_TYPES:
                        report.status = "FAIL"
                        report.status_extended = (
                            f"{prefix} authenticates with the stored credential "
                            f"type {connection.auth_type}, which carries no "
                            f"caller identity."
                        )
                    elif auth in NO_AUTH_TYPES:
                        report.status = "FAIL"
                        report.status_extended = (
                            f"{prefix} has no authentication configured."
                        )
                    else:
                        report.status = "MANUAL"
                        report.status_extended = (
                            f"{prefix} uses the authentication type "
                            f"{connection.auth_type}, which this check does not "
                            f"recognise. Confirm whether it presents a caller "
                            f"identity."
                        )
                    findings.append(report)
        return findings
