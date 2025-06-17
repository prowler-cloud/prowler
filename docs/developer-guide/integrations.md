# Creating a New Integration

## Introduction

Integrating Prowler with external tools enhances its functionality and enables seamless workflow automation. Prowler supports a variety of integrations to optimize security assessments and reporting.

### Supported Integration Targets

- Messaging Platforms – Example: Slack

- Project Management Tools – Example: Jira

- Cloud Services – Example: AWS Security Hub

### Integration Guidelines
To integrate Prowler with a specific product:

Refer to the [Prowler Developer Guide](https://docs.prowler.com/projects/prowler-open-source/en/latest/) to understand its architecture and integration mechanisms.

* Identify the most suitable integration method for the intended platform.

## Steps to Create an Integration

### Defining the Integration Purpose

* Before implementing an integration, clearly define its objective. Common purposes include:

    * Sending Prowler findings to a platform for alerting, tracking, or further analysis.
    * For inspiration and implementation examples, please review the existing integrations in the [`prowler/lib/outputs`](https://github.com/prowler-cloud/prowler/tree/master/prowler/lib/outputs) folder.

### Developing the Integration

* Script Development:

    * Write a script to process Prowler’s output and interact with the target platform’s API.
    * If the goal is to send findings, parse Prowler’s results and use the platform’s API to create entries or notifications.

* Configuration:

    * Ensure the script supports environment-specific settings, such as:

        - API endpoints

        - Authentication tokens

        - Any necessary configurable parameters.

### Fundamental Structure

* Integration Class:

    * To implement an integration, create a class that encapsulates the required attributes and methods for interacting with the target platform. Example: Jira Integration

    ```python title="Jira Class"
    class Jira:
    """
    Jira class to interact with the Jira API

    [Note]
    This integration is limited to a single Jira Cloud instance, meaning all issues will be created under the same Jira Cloud ID. Future improvements will include the ability to specify a Jira Cloud ID for users associated with multiple accounts.

    Attributes
        - _redirect_uri: The redirect URI used
        - _client_id: The client identifier
        - _client_secret: The client secret
        - _access_token: The access token
        - _refresh_token: The refresh token
        - _expiration_date: The authentication expiration
        - _cloud_id: The cloud identifier
        - _scopes: The scopes needed to authenticate, read:jira-user read:jira-work write:jira-work
        - AUTH_URL: The URL to authenticate with Jira
        - PARAMS_TEMPLATE: The template for the parameters to authenticate with Jira
        - TOKEN_URL: The URL to get the access token from Jira
        - API_TOKEN_URL: The URL to get the accessible resources from Jira

    Methods
        __init__: Initializes the Jira object
        - input_authorization_code: Inputs the authorization code
        - auth_code_url: Generates the URL to authorize the application
        - get_auth: Gets the access token and refreshes it
        - get_cloud_id: Gets the cloud identifier from Jira
        - get_access_token: Gets the access token
        - refresh_access_token: Refreshes the access token from Jira
        - test_connection: Tests the connection to Jira and returns a Connection object
        - get_projects: Gets the projects from Jira
        - get_available_issue_types: Gets the available issue types for a project
        - send_findings: Sends the findings to Jira and creates an issue

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

    * Validating Credentials or Tokens

        To ensure a successful connection to the target platform, implement a method that validates authentication credentials or tokens.

    #### Method Implementation

    The following example demonstrates the `test_connection` method for the `Jira` class:

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
            - redirect_uri: The redirect URI used
            - client_id: The client identifier
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

    #### Method Implementation

    The following example demonstrates the `send_findings` method for the `Jira` class:

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

### Testing the Integration

* Conduct integration testing in a controlled environment to validate expected behavior. Ensure the following:

    * Transmission Accuracy – Verify that Prowler findings are correctly sent and processed by the target platform.
    * Error Handling – Simulate edge cases to assess robustness and failure recovery mechanisms.

### Documentation

* Ensure the following elements are included:

    * Setup Instructions – List all necessary dependencies and installation steps.
    * Configuration Details – Specify required environment variables, authentication steps, etc.
    * Example Use Cases – Provide practical scenarios demonstrating functionality.
    * Troubleshooting Guide – Document common issues and resolution steps.
    * Comprehensive and clear documentation improves maintainability and simplifies onboarding.
