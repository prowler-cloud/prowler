import logging
import os

from jira import JIRA as JiraSDK

from prowler.lib.logger import logger
from prowler.lib.outputs.finding import Finding
from prowler.lib.outputs.jira.exceptions.exceptions import (
    JiraAuthenticationError,
    JiraGetProjectsError,
    JiraNoProjectsError,
    JiraTestConnectionError,
)
from prowler.providers.common.models import Connection


class Jira:
    def __init__(self, server_url, username, api_token):
        """
        Initialize a Jira object.

        Args:
            server_url (str): The Jira server URL.
            username (str): The Jira username.
            api_token (str): The Jira API token.
        """
        self.server_url = server_url
        self.username = username
        self.api_token = api_token
        self.jira = self.authenticate()

    def authenticate(self) -> JiraSDK:
        """
        Authenticate with Jira using the provided credentials.

        Returns:
            - JiraSDK: an authenticated JiraSDK object

        Raises:
            - JiraAuthenticationError: if the authentication fails
        """

        try:
            jira = JiraSDK(
                server=self.server_url, basic_auth=(self.username, self.api_token)
            )
            logging.info("Successfully authenticated with Jira")
            return jira
        except Exception as error:
            logger.critical(
                f"JiraAuthenticationError[{error.__traceback__.tb_lineno}]: {error}"
            )
            raise JiraAuthenticationError(
                original_exception=error, file=os.path.basename(__file__)
            )

    @staticmethod
    def test_connection(
        server_url: str = None,
        username: str = None,
        api_token: str = None,
        raise_on_exception: bool = True,
    ) -> Connection:
        """
        Test the connection to Jira using the provided credentials.

        Args:
            server_url (str): The Jira server URL.
            username (str): The Jira username.
            api_token (str): The Jira API token.
            raise_on_exception (bool): Whether to raise an exception if the connection test fails.

        Returns:
            - Connection: A Connection object with the connection status.

        Raises:
            - JiraTestConnectionError: if the connection test fails and raise_on_exception is True.
        """
        try:
            jira = JiraSDK(server=server_url, basic_auth=(username, api_token))
            user = jira.myself()
            logging.info(f"Authenticated as {user['displayName']}")
            return Connection(
                is_connected=True,
            )
        except Exception as error:
            logger.error(
                f"JiraConnectionError[{error.__traceback__.tb_lineno}]: {error}"
            )
            if raise_on_exception:
                raise JiraTestConnectionError(
                    file=os.path.basename(__file__), original_exception=error
                ) from error
            return Connection(error=error)

    def get_projects(self) -> list[dict]:
        """
        Fetch all projects from Jira.

        Returns:
            - list[dict]: A list of dictionaries containing the key and name of each project.

        Raises:
            - JiraGetProjectsError: if the request to get projects fails.
        """
        try:
            projects = self.jira.projects()
            project_objects = [
                {"key": project.key, "name": project.name} for project in projects
            ]

            if not project_objects:
                logging.error("No projects found in Jira")
                raise JiraNoProjectsError(
                    message="No projects found in Jira", file=os.path.basename(__file__)
                )
            return project_objects
        except Exception as e:
            logging.error(f"Failed to get projects: {e}")
            raise JiraGetProjectsError(
                original_exception=e, file=os.path.basename(__file__)
            )

    def send_findings(
        self,
        project_key: str = None,
        findings: list[Finding] = None,
        issue_type: str = "Bug",
    ):
        """
        Create Jira issues for the given findings.

        Args:
            project_key (str): The Jira project key.
            findings (list[Finding]): A list of Finding objects.
            issue_type (str): The issue type to create (default: "Bug").

        Raises:
            - JiraCreateIssueError: if the request to create an issue fails.
        """
        for finding in findings:
            try:
                issue_dict = {
                    "project": {"key": project_key},
                    "summary": finding["summary"],
                    "description": finding["description"],
                    "issuetype": {"name": issue_type},
                }
                new_issue = self.jira.create_issue(fields=issue_dict)
                print(f"Successfully created issue: {new_issue.key}")
            except Exception as e:
                logging.error(f"Failed to create issue: {e}")
