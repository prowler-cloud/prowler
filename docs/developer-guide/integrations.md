# Creating a New Integration

## Introduction

Integrating Prowler with external tools enhances its functionality and seamlessly embeds it into your workflows. Prowler supports a wide range of integrations to streamline security assessments and reporting. Common integration targets include messaging platforms like Slack, project management tools like Jira, and cloud services such as AWS Security Hub.

## Steps to Create a General Integration

### Identify the Integration Purpose

* Clearly define the objective of the integration. For example:
    * Sending Prowler findings to a platform for alerts, tracking, or further analysis.
    * Review existing integrations in the [`prowler/lib/outputs`](https://github.com/prowler-cloud/prowler/tree/master/prowler/lib/outputs) folder for inspiration and implementation examples.

### Review Prowler’s Integration Capabilities

* Consult the [Prowler Developer Guide](https://docs.prowler.com/projects/prowler-open-source/en/latest/) to understand how Prowler works and the way that you can integrate it with the desired product!
* Identify the best approach for the specific platform you’re targeting.

### Develop the Integration

* Script Development:
    * Write a script to process Prowler’s output and interact with the target platform’s API.
    * For example, to send findings, parse Prowler’s results and use the platform’s API to create entries or notifications.
* Configuration:
    * Ensure your script includes configurable options for environment-specific settings, such as API endpoints and authentication tokens.

### Fundamental Structure

* Integration Class:
    * Create a class that encapsulates attributes and methods for the integration.
    The following is the code for the `Jira` class:
    ```python title="Jira Class"
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

    # More properties and methods
    ```
* Test Connection Method:
    * Implement a method to validate credentials or tokens, ensuring the connection to the target platform is successful.
    The following is the code for the `test_connection` method for the `Jira` class:
    ```python title="Test connection"
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
    ```
* Send Findings Method:
    * Add a method to send Prowler findings to the target platform, adhering to its API specifications.
    The following is the code for the `send_findings` method for the `Jira` class:
    ```python title="Send findings method"
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
    ```

### Testing

* Test the integration in a controlled environment to confirm it behaves as expected.
* Verify that Prowler’s findings are accurately transmitted and correctly processed by the target platform.
* Simulate edge cases to ensure robust error handling.

### Documentation

* Provide clear, detailed documentation for your integration:
    * Setup instructions, including any required dependencies.
    * Configuration details, such as environment variables or authentication steps.
    * Example use cases and troubleshooting tips.
* Good documentation ensures maintainability and simplifies onboarding for team members.
