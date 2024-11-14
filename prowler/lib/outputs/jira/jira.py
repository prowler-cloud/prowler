import base64
import os
from datetime import datetime, timedelta
from typing import Dict

import requests
import requests.compat

from prowler.lib.logger import logger
from prowler.lib.outputs.finding import Finding
from prowler.lib.outputs.jira.exceptions.exceptions import (
    JiraAuthenticationError,
    JiraCreateIssueError,
    JiraGetAccessTokenError,
    JiraGetAuthResponseError,
    JiraGetAvailableIssueTypesError,
    JiraGetAvailableIssueTypesResponseError,
    JiraGetCloudIDError,
    JiraGetCloudIDNoResourcesError,
    JiraGetCloudIDResponseError,
    JiraGetProjectsError,
    JiraGetProjectsResponseError,
    JiraInvalidIssueTypeError,
    JiraInvalidProjectKeyError,
    JiraNoProjectsError,
    JiraNoTokenError,
    JiraRefreshTokenError,
    JiraRefreshTokenResponseError,
    JiraSendFindingsResponseError,
    JiraTestConnectionError,
)
from prowler.providers.common.models import Connection


class Jira:
    """
    Jira class to interact with the Jira API

    [Note]
    This integration is limited to a single Jira Cloud, therefore all the issues will be created for same Jira Cloud ID. We will need to work on the ability of providing a Jira Cloud ID if the user is present in more than one.

    Attributes:
        - _redirect_uri: The redirect URI
        - _client_id: The client ID
        - _client_secret: The client secret
        - _access_token: The access token
        - _refresh_token: The refresh token
        - _expiration_date: The authentication expiration
        - _cloud_id: The cloud ID
        - _scopes: The scopes needed to authenticate, read:jira-user read:jira-work write:jira-work
        - AUTH_URL: The URL to authenticate with Jira
        - PARAMS_TEMPLATE: The template for the parameters to authenticate with Jira
        - TOKEN_URL: The URL to get the access token from Jira
        - API_TOKEN_URL: The URL to get the accessible resources from Jira

    Methods:
        - __init__: Initialize the Jira object
        - input_authorization_code: Input the authorization code
        - auth_code_url: Generate the URL to authorize the application
        - get_auth: Get the access token and refresh token
        - get_cloud_id: Get the cloud ID from Jira
        - get_access_token: Get the access token
        - refresh_access_token: Refresh the access token from Jira
        - test_connection: Test the connection to Jira and return a Connection object
        - get_projects: Get the projects from Jira
        - get_available_issue_types: Get the available issue types for a project
        - send_findings: Send the findings to Jira and create an issue

    Raises:
        - JiraGetAuthResponseError: Failed to get the access token and refresh token
        - JiraGetCloudIDNoResourcesError: No resources were found in Jira when getting the cloud id
        - JiraGetCloudIDResponseError: Failed to get the cloud ID, response code did not match 200
        - JiraGetCloudIDError: Failed to get the cloud ID from Jira
        - JiraAuthenticationError: Failed to authenticate
        - JiraRefreshTokenError: Failed to refresh the access token
        - JiraRefreshTokenResponseError: Failed to refresh the access token, response code did not match 200
        - JiraGetAccessTokenError: Failed to get the access token
        - JiraNoProjectsError: No projects found in Jira
        - JiraGetProjectsError: Failed to get projects from Jira
        - JiraGetProjectsResponseError: Failed to get projects from Jira, response code did not match 200
        - JiraInvalidIssueTypeError: The issue type is invalid
        - JiraGetAvailableIssueTypesError: Failed to get available issue types from Jira
        - JiraGetAvailableIssueTypesResponseError: Failed to get available issue types from Jira, response code did not match 200
        - JiraCreateIssueError: Failed to create an issue in Jira
        - JiraSendFindingsResponseError: Failed to send the findings to Jira
        - JiraTestConnectionError: Failed to test the connection

    Usage:
        jira = Jira(
            redirect_uri="http://localhost:8080",
            client_id="client_id",
            client_secret="client_secret
        )
        jira.send_findings(findings=findings, project_key="KEY")
    """

    _redirect_uri: str = None
    _client_id: str = None
    _client_secret: str = None
    _access_token: str = None
    _refresh_token: str = None
    _expiration_date: int = None
    _cloud_id: str = None
    _scopes: list[str] = None
    AUTH_URL = "https://auth.atlassian.com/authorize"
    PARAMS_TEMPLATE = {
        "audience": "api.atlassian.com",
        "client_id": None,
        "scope": None,
        "redirect_uri": None,
        "state": None,
        "response_type": "code",
        "prompt": "consent",
    }
    TOKEN_URL = "https://auth.atlassian.com/oauth/token"
    API_TOKEN_URL = "https://api.atlassian.com/oauth/token/accessible-resources"

    def __init__(
        self,
        redirect_uri: str = None,
        client_id: str = None,
        client_secret: str = None,
    ):
        self._redirect_uri = redirect_uri
        self._client_id = client_id
        self._client_secret = client_secret
        self._scopes = ["read:jira-user", "read:jira-work", "write:jira-work"]
        auth_url = self.auth_code_url()
        authorization_code = self.input_authorization_code(auth_url)
        self.get_auth(authorization_code)

    @property
    def redirect_uri(self):
        return self._redirect_uri

    @property
    def client_id(self):
        return self._client_id

    @property
    def auth_expiration(self):
        return self._expiration_date

    @auth_expiration.setter
    def auth_expiration(self, value):
        self._expiration_date = value

    @property
    def cloud_id(self):
        return self._cloud_id

    @cloud_id.setter
    def cloud_id(self, value):
        self._cloud_id = value

    @property
    def scopes(self):
        return self._scopes

    def get_params(self, state_encoded):
        return {
            **self.PARAMS_TEMPLATE,
            "client_id": self.client_id,
            "scope": " ".join(self.scopes),
            "redirect_uri": self.redirect_uri,
            "state": state_encoded,
        }

    # TODO: Add static credentials for future use
    @staticmethod
    def input_authorization_code(auth_url: str = None) -> str:
        """Input the authorization code

        Args:
            - auth_url: The URL to authorize the application

        Returns:
            - str: The authorization code from Jira
        """
        print(f"Authorize the application by visiting this URL: {auth_url}")
        return input("Enter the authorization code from Jira: ")

    def auth_code_url(self) -> str:
        """Generate the URL to authorize the application

        Returns:
            - str: The URL to authorize the application

        Raises:
            - JiraGetAuthResponseError: Failed to get the access token and refresh token
        """
        # Generate the state parameter
        random_bytes = os.urandom(24)
        state_encoded = base64.urlsafe_b64encode(random_bytes).decode("utf-8")
        # Generate the URL
        params = self.get_params(state_encoded)

        return f"{self.AUTH_URL}?{requests.compat.urlencode(params)}"

    @staticmethod
    def get_timestamp_from_seconds(seconds: int) -> datetime:
        """Get the timestamp adding the seconds to the current time

        Args:
            - seconds: The seconds to add to the current time

        Returns:
            - datetime: The timestamp with the seconds added
        """
        return (datetime.now() + timedelta(seconds=seconds)).isoformat()

    def get_auth(self, auth_code: str = None) -> None:
        """Get the access token and refresh token

        Args:
            - auth_code: The authorization code from Jira

        Returns:
            - None

        Raises:
            - JiraGetAuthResponseError: Failed to get the access token and refresh token
            - JiraGetCloudIDNoResourcesError: No resources were found in Jira when getting the cloud id
            - JiraGetCloudIDResponseError: Failed to get the cloud ID, response code did not match 200
            - JiraGetCloudIDError: Failed to get the cloud ID from Jira
            - JiraAuthenticationError: Failed to authenticate
            - JiraRefreshTokenError: Failed to refresh the access token
            - JiraRefreshTokenResponseError: Failed to refresh the access token, response code did not match 200
            - JiraGetAccessTokenError: Failed to get the access token
        """
        try:
            body = {
                "grant_type": "authorization_code",
                "client_id": self.client_id,
                "client_secret": self._client_secret,
                "code": auth_code,
                "redirect_uri": self.redirect_uri,
            }

            headers = {"Content-Type": "application/json"}
            response = requests.post(self.TOKEN_URL, json=body, headers=headers)

            if response.status_code == 200:
                tokens = response.json()
                self._access_token = tokens.get("access_token")
                self._refresh_token = tokens.get("refresh_token")
                self._expiration_date = self.get_timestamp_from_seconds(
                    tokens.get("expires_in")
                )
                self._cloud_id = self.get_cloud_id(self._access_token)
            else:
                response_error = (
                    f"Failed to get auth: {response.status_code} - {response.json()}"
                )
                raise JiraGetAuthResponseError(
                    message=response_error, file=os.path.basename(__file__)
                )
        except JiraGetCloudIDNoResourcesError as no_resources_error:
            raise no_resources_error
        except JiraGetCloudIDResponseError as response_error:
            raise response_error
        except JiraGetCloudIDError as cloud_id_error:
            raise cloud_id_error
        except Exception as e:
            message_error = f"Failed to get auth: {e}"
            logger.error(message_error)
            raise JiraAuthenticationError(
                message=message_error,
                file=os.path.basename(__file__),
            )

    def get_cloud_id(self, access_token: str = None) -> str:
        """Get the cloud ID from Jira

        Args:
            - access_token: The access token from Jira

        Returns:
            - str: The cloud ID

        Raises:
            - JiraGetCloudIDNoResourcesError: No resources were found in Jira when getting the cloud id
            - JiraGetCloudIDResponseError: Failed to get the cloud ID, response code did not match 200
            - JiraGetCloudIDError: Failed to get the cloud ID from Jira
        """
        try:
            headers = {"Authorization": f"Bearer {access_token}"}
            response = requests.get(self.API_TOKEN_URL, headers=headers)

            if response.status_code == 200:
                resources = response.json()
                if len(resources) > 0:
                    return resources[0].get("id")
                else:
                    error_message = (
                        "No resources were found in Jira when getting the cloud id"
                    )
                    logger.error(error_message)
                    raise JiraGetCloudIDNoResourcesError(
                        message=error_message,
                        file=os.path.basename(__file__),
                    )
            else:
                response_error = f"Failed to get cloud id: {response.status_code} - {response.json()}"
                logger.warning(response_error)
                raise JiraGetCloudIDResponseError(
                    message=response_error, file=os.path.basename(__file__)
                )
        except Exception as e:
            error_message = f"Failed to get the cloud ID from Jira: {e}"
            logger.error(error_message)
            raise JiraGetCloudIDError(
                message=error_message,
                file=os.path.basename(__file__),
            )

    def get_access_token(self) -> str:
        """Get the access token

        Returns:
            - str: The access token

        Raises:
            - JiraRefreshTokenError: Failed to refresh the access token
            - JiraRefreshTokenResponseError: Failed to refresh the access token, response code did not match 200
            - JiraGetAccessTokenError: Failed to get the access token
        """
        try:
            if self.auth_expiration and datetime.now() < datetime.fromisoformat(
                self.auth_expiration
            ):
                return self._access_token
            else:
                return self.refresh_access_token()
        except JiraRefreshTokenError as refresh_error:
            raise refresh_error
        except JiraRefreshTokenResponseError as response_error:
            raise response_error
        except Exception as e:
            logger.error(f"Failed to get access token: {e}")
            raise JiraGetAccessTokenError(
                message="Failed to get the access token",
                file=os.path.basename(__file__),
            )

    def refresh_access_token(self) -> str:
        """Refresh the access token

        Returns:
            - str: The access token

        Raises:
            - JiraRefreshTokenError: Failed to refresh the access token
            - JiraRefreshTokenResponseError: Failed to refresh the access token, response code did not match 200
        """
        try:
            url = "https://auth.atlassian.com/oauth/token"
            body = {
                "grant_type": "refresh_token",
                "client_id": self.client_id,
                "client_secret": self._client_secret,
                "refresh_token": self._refresh_token,
            }

            headers = {"Content-Type": "application/json"}
            response = requests.post(url, json=body, headers=headers)

            if response.status_code == 200:
                tokens = response.json()
                self._access_token = tokens.get("access_token")
                self._refresh_token = tokens.get("refresh_token")
                self._expiration_date = self.get_timestamp_from_seconds(
                    tokens.get("expires_in")
                )
                return self._access_token
            else:
                response_error = f"Failed to refresh access token: {response.status_code} - {response.json()}"
                logger.warning(response_error)
                raise JiraRefreshTokenResponseError(
                    message=response_error, file=os.path.basename(__file__)
                )

        except Exception as e:
            logger.error(f"Failed to refresh access token: {e}")
            raise JiraRefreshTokenError(
                message="Failed to refresh the access token",
                file=os.path.basename(__file__),
            )

    @staticmethod
    def test_connection(
        redirect_uri: str = None,
        client_id: str = None,
        client_secret: str = None,
        raise_on_exception: bool = True,
    ) -> Connection:
        """Test the connection to Jira

        Args:
            - redirect_uri: The redirect URI
            - client_id: The client ID
            - client_secret: The client secret
            - raise_on_exception: Whether to raise an exception or not

        Returns:
            - Connection: The connection object

        Raises:
            - JiraGetCloudIDNoResourcesError: No resources were found in Jira when getting the cloud id
            - JiraGetCloudIDResponseError: Failed to get the cloud ID, response code did not match 200
            - JiraGetCloudIDError: Failed to get the cloud ID from Jira
            - JiraAuthenticationError: Failed to authenticate
            - JiraTestConnectionError: Failed to test the connection
        """
        try:
            jira = Jira(
                redirect_uri=redirect_uri,
                client_id=client_id,
                client_secret=client_secret,
            )
            access_token = jira.get_access_token()

            if not access_token:
                return ValueError("Failed to get access token")

            headers = {"Authorization": f"Bearer {access_token}"}
            response = requests.get(
                f"https://api.atlassian.com/ex/jira/{jira.cloud_id}/rest/api/3/myself",
                headers=headers,
            )

            if response.status_code == 200:
                return Connection(is_connected=True)
            else:
                return Connection(is_connected=False, error=response.json())
        except JiraGetCloudIDNoResourcesError as no_resources_error:
            logger.error(
                f"{no_resources_error.__class__.__name__}[{no_resources_error.__traceback__.tb_lineno}]: {no_resources_error}"
            )
            if raise_on_exception:
                raise no_resources_error
            return Connection(error=no_resources_error)
        except JiraGetCloudIDResponseError as response_error:
            logger.error(
                f"{response_error.__class__.__name__}[{response_error.__traceback__.tb_lineno}]: {response_error}"
            )
            if raise_on_exception:
                raise response_error
            return Connection(error=response_error)
        except JiraGetCloudIDError as cloud_id_error:
            logger.error(
                f"{cloud_id_error.__class__.__name__}[{cloud_id_error.__traceback__.tb_lineno}]: {cloud_id_error}"
            )
            if raise_on_exception:
                raise cloud_id_error
            return Connection(error=cloud_id_error)
        except JiraAuthenticationError as auth_error:
            logger.error(
                f"{auth_error.__class__.__name__}[{auth_error.__traceback__.tb_lineno}]: {auth_error}"
            )
            if raise_on_exception:
                raise auth_error
            return Connection(error=auth_error)
        except Exception as error:
            logger.error(f"Failed to test connection: {error}")
            if raise_on_exception:
                raise JiraTestConnectionError(
                    message="Failed to test connection on the Jira integration",
                    file=os.path.basename(__file__),
                )
            return Connection(is_connected=False, error=error)

    def get_projects(self) -> Dict[str, str]:
        """Get the projects from Jira

        Returns:
            - list[Dict[str, str]]: The projects from Jira as a list of dictionaries, the projects format is [{"key": "KEY", "name": "NAME"}]

        Raises:
            - JiraNoProjectsError: No projects found in Jira
            - JiraGetProjectsError: Failed to get projects from Jira
            - JiraRefreshTokenError: Failed to refresh the access token
            - JiraRefreshTokenResponseError: Failed to refresh the access token, response code did not match
            - JiraGetProjectsResponseError: Failed to get projects from Jira, response code did not match 200
        """
        try:
            access_token = self.get_access_token()

            if not access_token:
                return ValueError("Failed to get access token")

            headers = {"Authorization": f"Bearer {access_token}"}
            response = requests.get(
                f"https://api.atlassian.com/ex/jira/{self.cloud_id}/rest/api/3/project",
                headers=headers,
            )

            if response.status_code == 200:
                # Return the Project Key and Name, using only a dictionary
                projects = {
                    project["key"]: project["name"] for project in response.json()
                }
                if len(projects) == 0:
                    logger.error("No projects found")
                    raise JiraNoProjectsError(
                        message="No projects found in Jira",
                        file=os.path.basename(__file__),
                    )
                return projects
            else:
                logger.error(
                    f"Failed to get projects: {response.status_code} - {response.json()}"
                )
                raise JiraGetProjectsResponseError(
                    message="Failed to get projects from Jira",
                    file=os.path.basename(__file__),
                )
        except JiraNoProjectsError as no_projects_error:
            raise no_projects_error
        except JiraRefreshTokenError as refresh_error:
            raise refresh_error
        except JiraRefreshTokenResponseError as response_error:
            raise response_error
        except Exception as e:
            logger.error(f"Failed to get projects: {e}")
            raise JiraGetProjectsError(
                message="Failed to get projects from Jira",
                file=os.path.basename(__file__),
            )

    def get_available_issue_types(self, project_key: str = None) -> list[str]:
        """Get the available issue types for a project

        Args:
            - project_key: The project key

        Returns:
            - list[str]: The available issue types

        Raises:
            - JiraRefreshTokenError: Failed to refresh the access token
            - JiraRefreshTokenResponseError: Failed to refresh the access token, response code did not match 200
            - JiraGetAccessTokenError: Failed to get the access token
            - JiraGetAuthResponseError: Failed to authenticate with Jira
            - JiraGetProjectsError: Failed to get projects from Jira
            - JiraGetProjectsResponseError: Failed to get projects from Jira, response code did not match 200
        """

        try:
            access_token = self.get_access_token()

            if not access_token:
                return JiraNoTokenError(
                    message="No token was found",
                    file=os.path.basename(__file__),
                )

            headers = {"Authorization": f"Bearer {access_token}"}
            response = requests.get(
                f"https://api.atlassian.com/ex/jira/{self.cloud_id}/rest/api/3/issue/createmeta?projectKeys={project_key}&expand=projects.issuetypes.fields",
                headers=headers,
            )

            if response.status_code == 200:
                if len(response.json()["projects"]) == 0:
                    logger.error("No projects found")
                    raise JiraNoProjectsError(
                        message="No projects found in Jira",
                        file=os.path.basename(__file__),
                    )
                issue_types = response.json()["projects"][0]["issuetypes"]
                return [issue_type["name"] for issue_type in issue_types]
            else:
                response_error = f"Failed to get available issue types: {response.status_code} - {response.json()}"
                logger.warning(response_error)
                raise JiraGetAvailableIssueTypesResponseError(
                    message=response_error, file=os.path.basename(__file__)
                )
        except JiraRefreshTokenError as refresh_error:
            raise refresh_error
        except JiraRefreshTokenResponseError as response_error:
            raise response_error
        except Exception as e:
            logger.error(f"Failed to get available issue types: {e}")
            raise JiraGetAvailableIssueTypesError(
                message="Failed to get available issue types",
                file=os.path.basename(__file__),
            )

    @staticmethod
    def get_color_from_status(status: str) -> str:
        """Get the color from the status

        Args:
            - status: The status of the finding

        Returns:
            - str: The color of the status
        """
        if status == "PASS":
            return "#008000"
        if status == "FAIL":
            return "#FF0000"
        if status == "MUTED":
            return "#FFA500"

    @staticmethod
    def get_adf_description(
        check_id: str = None,
        check_title: str = None,
        severity: str = None,
        status: str = None,
        status_color: str = None,
        status_extended: str = None,
        provider: str = None,
        region: str = None,
        resource_uid: str = None,
        resource_name: str = None,
        risk: str = None,
        recommendation_text: str = None,
        recommendation_url: str = None,
    ) -> dict:
        return {
            "type": "doc",
            "version": 1,
            "content": [
                {
                    "type": "paragraph",
                    "content": [
                        {
                            "type": "text",
                            "text": "Prowler has discovered the following finding:",
                        }
                    ],
                },
                {
                    "type": "table",
                    "attrs": {"layout": "full-width"},
                    "content": [
                        {
                            "type": "tableRow",
                            "content": [
                                {
                                    "type": "tableCell",
                                    "attrs": {"colwidth": [1]},
                                    "content": [
                                        {
                                            "type": "paragraph",
                                            "content": [
                                                {
                                                    "type": "text",
                                                    "text": "Check Id",
                                                    "marks": [{"type": "strong"}],
                                                }
                                            ],
                                        }
                                    ],
                                },
                                {
                                    "type": "tableCell",
                                    "attrs": {"colwidth": [3]},
                                    "content": [
                                        {
                                            "type": "paragraph",
                                            "content": [
                                                {
                                                    "type": "text",
                                                    "text": check_id,
                                                    "marks": [{"type": "code"}],
                                                }
                                            ],
                                        }
                                    ],
                                },
                            ],
                        },
                        {
                            "type": "tableRow",
                            "content": [
                                {
                                    "type": "tableCell",
                                    "attrs": {"colwidth": [1]},
                                    "content": [
                                        {
                                            "type": "paragraph",
                                            "content": [
                                                {
                                                    "type": "text",
                                                    "text": "Check Title",
                                                    "marks": [{"type": "strong"}],
                                                }
                                            ],
                                        }
                                    ],
                                },
                                {
                                    "type": "tableCell",
                                    "attrs": {"colwidth": [3]},
                                    "content": [
                                        {
                                            "type": "paragraph",
                                            "content": [
                                                {
                                                    "type": "text",
                                                    "text": check_title,
                                                }
                                            ],
                                        }
                                    ],
                                },
                            ],
                        },
                        {
                            "type": "tableRow",
                            "content": [
                                {
                                    "type": "tableCell",
                                    "attrs": {"colwidth": [1]},
                                    "content": [
                                        {
                                            "type": "paragraph",
                                            "content": [
                                                {
                                                    "type": "text",
                                                    "text": "Severity",
                                                    "marks": [{"type": "strong"}],
                                                }
                                            ],
                                        }
                                    ],
                                },
                                {
                                    "type": "tableCell",
                                    "attrs": {"colwidth": [3]},
                                    "content": [
                                        {
                                            "type": "paragraph",
                                            "content": [
                                                {
                                                    "type": "text",
                                                    "text": severity,
                                                }
                                            ],
                                        }
                                    ],
                                },
                            ],
                        },
                        {
                            "type": "tableRow",
                            "content": [
                                {
                                    "type": "tableCell",
                                    "attrs": {"colwidth": [1]},
                                    "content": [
                                        {
                                            "type": "paragraph",
                                            "content": [
                                                {
                                                    "type": "text",
                                                    "text": "Status",
                                                    "marks": [{"type": "strong"}],
                                                }
                                            ],
                                        }
                                    ],
                                },
                                {
                                    "type": "tableCell",
                                    "attrs": {"colwidth": [3]},
                                    "content": [
                                        {
                                            "type": "paragraph",
                                            "content": [
                                                {
                                                    "type": "text",
                                                    "text": status,
                                                    "marks": [
                                                        {"type": "strong"},
                                                        {
                                                            "type": "textColor",
                                                            "attrs": {
                                                                "color": status_color
                                                            },
                                                        },
                                                    ],
                                                }
                                            ],
                                        }
                                    ],
                                },
                            ],
                        },
                        {
                            "type": "tableRow",
                            "content": [
                                {
                                    "type": "tableCell",
                                    "attrs": {"colwidth": [1]},
                                    "content": [
                                        {
                                            "type": "paragraph",
                                            "content": [
                                                {
                                                    "type": "text",
                                                    "text": "Status Extended",
                                                    "marks": [{"type": "strong"}],
                                                }
                                            ],
                                        }
                                    ],
                                },
                                {
                                    "type": "tableCell",
                                    "attrs": {"colwidth": [3]},
                                    "content": [
                                        {
                                            "type": "paragraph",
                                            "content": [
                                                {
                                                    "type": "text",
                                                    "text": status_extended,
                                                }
                                            ],
                                        }
                                    ],
                                },
                            ],
                        },
                        {
                            "type": "tableRow",
                            "content": [
                                {
                                    "type": "tableCell",
                                    "attrs": {"colwidth": [1]},
                                    "content": [
                                        {
                                            "type": "paragraph",
                                            "content": [
                                                {
                                                    "type": "text",
                                                    "text": "Provider",
                                                    "marks": [{"type": "strong"}],
                                                }
                                            ],
                                        }
                                    ],
                                },
                                {
                                    "type": "tableCell",
                                    "attrs": {"colwidth": [3]},
                                    "content": [
                                        {
                                            "type": "paragraph",
                                            "content": [
                                                {
                                                    "type": "text",
                                                    "text": provider,
                                                    "marks": [{"type": "code"}],
                                                }
                                            ],
                                        }
                                    ],
                                },
                            ],
                        },
                        {
                            "type": "tableRow",
                            "content": [
                                {
                                    "type": "tableCell",
                                    "attrs": {"colwidth": [1]},
                                    "content": [
                                        {
                                            "type": "paragraph",
                                            "content": [
                                                {
                                                    "type": "text",
                                                    "text": "Region",
                                                    "marks": [{"type": "strong"}],
                                                }
                                            ],
                                        }
                                    ],
                                },
                                {
                                    "type": "tableCell",
                                    "attrs": {"colwidth": [3]},
                                    "content": [
                                        {
                                            "type": "paragraph",
                                            "content": [
                                                {
                                                    "type": "text",
                                                    "text": region,
                                                    "marks": [{"type": "code"}],
                                                }
                                            ],
                                        }
                                    ],
                                },
                            ],
                        },
                        {
                            "type": "tableRow",
                            "content": [
                                {
                                    "type": "tableCell",
                                    "attrs": {"colwidth": [1]},
                                    "content": [
                                        {
                                            "type": "paragraph",
                                            "content": [
                                                {
                                                    "type": "text",
                                                    "text": "Resource UID",
                                                    "marks": [{"type": "strong"}],
                                                }
                                            ],
                                        }
                                    ],
                                },
                                {
                                    "type": "tableCell",
                                    "attrs": {"colwidth": [3]},
                                    "content": [
                                        {
                                            "type": "paragraph",
                                            "content": [
                                                {
                                                    "type": "text",
                                                    "text": resource_uid,
                                                    "marks": [{"type": "code"}],
                                                }
                                            ],
                                        }
                                    ],
                                },
                            ],
                        },
                        {
                            "type": "tableRow",
                            "content": [
                                {
                                    "type": "tableCell",
                                    "attrs": {"colwidth": [1]},
                                    "content": [
                                        {
                                            "type": "paragraph",
                                            "content": [
                                                {
                                                    "type": "text",
                                                    "text": "Resource Name",
                                                    "marks": [{"type": "strong"}],
                                                }
                                            ],
                                        }
                                    ],
                                },
                                {
                                    "type": "tableCell",
                                    "attrs": {"colwidth": [3]},
                                    "content": [
                                        {
                                            "type": "paragraph",
                                            "content": [
                                                {
                                                    "type": "text",
                                                    "text": resource_name,
                                                    "marks": [{"type": "code"}],
                                                }
                                            ],
                                        }
                                    ],
                                },
                            ],
                        },
                        {
                            "type": "tableRow",
                            "content": [
                                {
                                    "type": "tableCell",
                                    "attrs": {"colwidth": [1]},
                                    "content": [
                                        {
                                            "type": "paragraph",
                                            "content": [
                                                {
                                                    "type": "text",
                                                    "text": "Risk",
                                                    "marks": [{"type": "strong"}],
                                                }
                                            ],
                                        }
                                    ],
                                },
                                {
                                    "type": "tableCell",
                                    "attrs": {"colwidth": [3]},
                                    "content": [
                                        {
                                            "type": "paragraph",
                                            "content": [
                                                {
                                                    "type": "text",
                                                    "text": risk,
                                                }
                                            ],
                                        }
                                    ],
                                },
                            ],
                        },
                        {
                            "type": "tableRow",
                            "content": [
                                {
                                    "type": "tableCell",
                                    "attrs": {"colwidth": [1]},
                                    "content": [
                                        {
                                            "type": "paragraph",
                                            "content": [
                                                {
                                                    "type": "text",
                                                    "text": "Recommendation",
                                                    "marks": [{"type": "strong"}],
                                                }
                                            ],
                                        }
                                    ],
                                },
                                {
                                    "type": "tableCell",
                                    "attrs": {"colwidth": [3]},
                                    "content": [
                                        {
                                            "type": "paragraph",
                                            "content": [
                                                {
                                                    "type": "text",
                                                    "text": recommendation_text + " ",
                                                },
                                                {
                                                    "type": "text",
                                                    "text": recommendation_url,
                                                    "marks": [
                                                        {
                                                            "type": "link",
                                                            "attrs": {
                                                                "href": recommendation_url
                                                            },
                                                        }
                                                    ],
                                                },
                                            ],
                                        }
                                    ],
                                },
                            ],
                        },
                    ],
                },
            ],
        }

    def send_findings(
        self,
        findings: list[Finding] = None,
        project_key: str = None,
        issue_type: str = None,
    ):
        """
        Send the findings to Jira

        Args:
            - findings: The findings to send
            - project_key: The project key
            - issue_type: The issue type

        Raises:
            - JiraRefreshTokenError: Failed to refresh the access token
            - JiraRefreshTokenResponseError: Failed to refresh the access token, response code did not match 200
            - JiraCreateIssueError: Failed to create an issue in Jira
            - JiraSendFindingsResponseError: Failed to send the findings to Jira
        """
        try:
            access_token = self.get_access_token()

            if not access_token:
                raise JiraNoTokenError(
                    message="No token was found",
                    file=os.path.basename(__file__),
                )

            projects = self.get_projects()

            if project_key not in projects:
                logger.error("The project key is invalid")
                raise JiraInvalidProjectKeyError(
                    message="The project key is invalid",
                    file=os.path.basename(__file__),
                )

            available_issue_types = self.get_available_issue_types(project_key)

            if issue_type not in available_issue_types:
                logger.error("The issue type is invalid")
                raise JiraInvalidIssueTypeError(
                    message="The issue type is invalid", file=os.path.basename(__file__)
                )
            headers = {
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json",
            }

            for finding in findings:
                status_color = self.get_color_from_status(finding.status.value)
                adf_description = self.get_adf_description(
                    check_id=finding.metadata.CheckID,
                    check_title=finding.metadata.CheckTitle,
                    severity=finding.metadata.Severity.value.upper(),
                    status=finding.status.value,
                    status_color=status_color,
                    status_extended=finding.status_extended,
                    provider=finding.metadata.Provider,
                    region=finding.region,
                    resource_uid=finding.resource_uid,
                    resource_name=finding.resource_name,
                    risk=finding.metadata.Risk,
                    recommendation_text=finding.metadata.Remediation.Recommendation.Text,
                    recommendation_url=finding.metadata.Remediation.Recommendation.Url,
                )
                payload = {
                    "fields": {
                        "project": {"key": project_key},
                        "summary": f"[Prowler] {finding.metadata.Severity.value.upper()} - {finding.metadata.CheckID} - {finding.resource_uid}",
                        "description": adf_description,
                        "issuetype": {"name": issue_type},
                    }
                }

                response = requests.post(
                    f"https://api.atlassian.com/ex/jira/{self.cloud_id}/rest/api/3/issue",
                    json=payload,
                    headers=headers,
                )

                if response.status_code != 201:
                    response_error = f"Failed to send finding: {response.status_code} - {response.json()}"
                    logger.warning(response_error)
                    raise JiraSendFindingsResponseError(
                        message=response_error, file=os.path.basename(__file__)
                    )
                else:
                    logger.info(f"Finding sent successfully: {response.json()}")
        except JiraRefreshTokenError as refresh_error:
            raise refresh_error
        except JiraRefreshTokenResponseError as response_error:
            raise response_error
        except Exception as e:
            logger.error(f"Failed to send findings: {e}")
            raise JiraCreateIssueError(
                message="Failed to create an issue in Jira",
                file=os.path.basename(__file__),
            )
