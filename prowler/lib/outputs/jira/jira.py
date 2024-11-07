import base64
import os

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
    JiraGetCloudIdError,
    JiraGetCloudIdNoResourcesError,
    JiraGetCloudIdResponseError,
    JiraGetProjectsError,
    JiraGetProjectsResponseError,
    JiraInvalidIssueTypeError,
    JiraNoProjectsError,
    JiraRefreshTokenError,
    JiraRefreshTokenResponseError,
    JiraSendFindingsResponseError,
    JiraTestConnectionError,
)
from prowler.providers.common.models import Connection


class Jira:
    _redirect_uri: str = None
    _client_id: str = None
    _client_secret: str = None
    _state_param: str = None
    _access_token: str = None
    _refresh_token: str = None
    _auth_expiration: int = None
    _cloud_id: str = None
    _scopes: list[str] = None

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
    def client_secret(self):
        return self._client_secret

    @property
    def state_param(self):
        return self._state_param

    @property
    def access_token(self):
        return self._access_token

    @access_token.setter
    def access_token(self, value):
        self._access_token = value

    @property
    def refresh_token(self):
        return self._refresh_token

    @property
    def auth_expiration(self):
        return self._auth_expiration

    @auth_expiration.setter
    def auth_expiration(self, value):
        self._auth_expiration = value

    @property
    def cloud_id(self):
        return self._cloud_id

    @cloud_id.setter
    def cloud_id(self, value):
        self._cloud_id = value

    @property
    def scopes(self):
        return self._scopes

    @staticmethod
    def input_authorization_code(auth_url: str = None) -> str:
        print(f"Authorize the application by visiting this URL: {auth_url}")
        return input("Enter the authorization code from Jira: ")

    def auth_code_url(self) -> str:
        """Generate the URL to authorize the application"""
        # Generate the state parameter
        random_bytes = os.urandom(24)
        state_encoded = base64.urlsafe_b64encode(random_bytes).decode("utf-8")
        self._state_param = state_encoded
        # Generate the URL
        params = {
            "audience": "api.atlassian.com",
            "client_id": self.client_id,
            "scope": " ".join(self.scopes),
            "redirect_uri": self.redirect_uri,
            "state": state_encoded,
            "response_type": "code",
            "prompt": "consent",
        }

        return (
            f"https://auth.atlassian.com/authorize?{requests.compat.urlencode(params)}"
        )

    def get_auth(self, auth_code: str = None) -> None:
        """Get the access token and refresh token

        Args:
            - auth_code: The authorization code from Jira

        Returns:
            - None

        Raises:
            - JiraGetAuthResponseError: Failed to get the access token and refresh token
            - JiraGetCloudIdNoResourcesError: No resources were found in Jira when getting the cloud id
            - JiraGetCloudIdResponseError: Failed to get the cloud ID, response code did not match 200
            - JiraGetCloudIdError: Failed to get the cloud ID from Jira
            - JiraAuthenticationError: Failed to authenticate
            - JiraRefreshTokenError: Failed to refresh the access token
            - JiraRefreshTokenResponseError: Failed to refresh the access token, response code did not match 200
            - JiraGetAccessTokenError: Failed to get the access token
        """
        try:
            url = "https://auth.atlassian.com/oauth/token"
            body = {
                "grant_type": "authorization_code",
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "code": auth_code,
                "redirect_uri": self.redirect_uri,
            }

            headers = {"Content-Type": "application/json"}
            response = requests.post(url, json=body, headers=headers)

            if response.status_code == 200:
                tokens = response.json()
                self._access_token = tokens.get("access_token")
                self._refresh_token = tokens.get("refresh_token")
                self._auth_expiration = tokens.get("expires_in")
                self._cloud_id = self.get_cloud_id(self.access_token)
            else:
                response_error = (
                    f"Failed to get auth: {response.status_code} - {response.json()}"
                )
                raise JiraGetAuthResponseError(
                    message=response_error, file=os.path.basename(__file__)
                )
        except JiraGetCloudIdNoResourcesError as no_resources_error:
            raise no_resources_error
        except JiraGetCloudIdResponseError as response_error:
            raise response_error
        except JiraGetCloudIdError as cloud_id_error:
            raise cloud_id_error
        except Exception as e:
            logger.error(f"Failed to get auth: {e}")
            raise JiraAuthenticationError(
                message="Failed to authenticate with Jira",
                file=os.path.basename(__file__),
            )

    def get_cloud_id(self, access_token: str = None) -> str:
        """Get the cloud ID from Jira

        Args:
            - access_token: The access token from Jira

        Returns:
            - str: The cloud ID

        Raises:
            - JiraGetCloudIdNoResourcesError: No resources were found in Jira when getting the cloud id
            - JiraGetCloudIdResponseError: Failed to get the cloud ID, response code did not match 200
            - JiraGetCloudIdError: Failed to get the cloud ID from Jira
        """
        try:
            url = "https://api.atlassian.com/oauth/token/accessible-resources"
            headers = {"Authorization": f"Bearer {access_token}"}
            response = requests.get(url, headers=headers)

            if response.status_code == 200:
                resources = response.json()
                if len(resources) > 0:
                    return resources[0].get("id")
                else:
                    logger.error("No resources found")
                    raise JiraGetCloudIdNoResourcesError(
                        message="No resources were found in Jira when getting the cloud id",
                        file=os.path.basename(__file__),
                    )
            else:
                response_error = f"Failed to get cloud id: {response.status_code} - {response.json()}"
                logger.warning(response_error)
                raise JiraGetCloudIdResponseError(
                    message=response_error, file=os.path.basename(__file__)
                )
        except Exception as e:
            logger.error(f"Failed to get cloud id: {e}")
            raise JiraGetCloudIdError(
                message="Failed to get the cloud ID from Jira",
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
            if self.auth_expiration and self.auth_expiration > 0:
                return self.access_token
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
                "client_secret": self.client_secret,
                "refresh_token": self.refresh_token,
            }

            headers = {"Content-Type": "application/json"}
            response = requests.post(url, json=body, headers=headers)

            if response.status_code == 200:
                tokens = response.json()
                self._access_token = tokens.get("access_token")
                self._refresh_token = tokens.get("refresh_token")
                self._auth_expiration = tokens.get("expires_in")
                return self.access_token
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
            - JiraGetCloudIdNoResourcesError: No resources were found in Jira when getting the cloud id
            - JiraGetCloudIdResponseError: Failed to get the cloud ID, response code did not match 200
            - JiraGetCloudIdError: Failed to get the cloud ID from Jira
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
        except JiraGetCloudIdNoResourcesError as no_resources_error:
            logger.error(
                f"{no_resources_error.__class__.__name__}[{no_resources_error.__traceback__.tb_lineno}]: {no_resources_error}"
            )
            if raise_on_exception:
                raise no_resources_error
            return Connection(error=no_resources_error)
        except JiraGetCloudIdResponseError as response_error:
            logger.error(
                f"{response_error.__class__.__name__}[{response_error.__traceback__.tb_lineno}]: {response_error}"
            )
            if raise_on_exception:
                raise response_error
            return Connection(error=response_error)
        except JiraGetCloudIdError as cloud_id_error:
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

    def get_projects(self) -> list[dict]:
        """Get the projects from Jira

        Returns:
            - list[dict]: The projects following the format {"key": str, "name": str}

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
                # Return the Project Key and Name
                projects = [
                    {"key": project.get("key"), "name": project.get("name")}
                    for project in response.json()
                ]
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
                return ValueError("Failed to get access token")

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
                # Must be replaced with proper error handling from custom exceptions
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

    def send_findings(
        self,
        findings: list[Finding] = None,
        project_key: str = None,
        issue_type: str = "Bug",
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
                return ValueError("Failed to get access token")

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
                if finding.status.value == "PASS":
                    status_color = "#008000"
                else:
                    status_color = "#FF0000"

                adf_description = {
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
                                                            "marks": [
                                                                {"type": "strong"}
                                                            ],
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
                                                            "text": finding.metadata.CheckID,
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
                                                            "marks": [
                                                                {"type": "strong"}
                                                            ],
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
                                                            "text": finding.metadata.CheckTitle,
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
                                                            "marks": [
                                                                {"type": "strong"}
                                                            ],
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
                                                            "text": finding.metadata.Severity.value.upper(),
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
                                                            "marks": [
                                                                {"type": "strong"}
                                                            ],
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
                                                            "text": finding.status.value,
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
                                                            "marks": [
                                                                {"type": "strong"}
                                                            ],
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
                                                            "text": finding.status_extended,
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
                                                            "marks": [
                                                                {"type": "strong"}
                                                            ],
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
                                                            "text": finding.metadata.Provider,
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
                                                            "marks": [
                                                                {"type": "strong"}
                                                            ],
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
                                                            "text": finding.region,
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
                                                            "marks": [
                                                                {"type": "strong"}
                                                            ],
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
                                                            "text": finding.resource_uid,
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
                                                            "marks": [
                                                                {"type": "strong"}
                                                            ],
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
                                                            "text": finding.resource_name,
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
                                                            "marks": [
                                                                {"type": "strong"}
                                                            ],
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
                                                            "text": finding.metadata.Risk,
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
                                                            "marks": [
                                                                {"type": "strong"}
                                                            ],
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
                                                            "text": finding.metadata.Remediation.Recommendation.Text
                                                            + " ",
                                                        },
                                                        {
                                                            "type": "text",
                                                            "text": finding.metadata.Remediation.Recommendation.Url,
                                                            "marks": [
                                                                {
                                                                    "type": "link",
                                                                    "attrs": {
                                                                        "href": finding.metadata.Remediation.Recommendation.Url
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
