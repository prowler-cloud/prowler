import base64
import os
import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Dict, List, Optional

import requests
import requests.compat
from markdown_it import MarkdownIt
from markdown_it.token import Token

from prowler.lib.logger import logger
from prowler.lib.outputs.finding import Finding
from prowler.lib.outputs.jira.exceptions.exceptions import (
    JiraAuthenticationError,
    JiraBasicAuthError,
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
    JiraInvalidParameterError,
    JiraInvalidProjectKeyError,
    JiraNoProjectsError,
    JiraNoTokenError,
    JiraRefreshTokenError,
    JiraRefreshTokenResponseError,
    JiraRequiredCustomFieldsError,
    JiraSendFindingsResponseError,
    JiraTestConnectionError,
)
from prowler.providers.common.models import Connection

ATLASSIAN_SITE_NAME_REGEX = re.compile(
    r"\A[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\Z"
)


@dataclass
class JiraConnection(Connection):
    """
    Represents a Jira connection object.
    Attributes:
        projects (dict): Dictionary of projects in Jira.
        issue_types (dict): Dictionary of issue types per project key.
    """

    projects: dict = None
    issue_types: dict = None


def _format_jira_issue_creation_error(response_json: object, status_code: int) -> str:
    """Build a safe Jira issue creation error message from structured fields.

    Args:
        response_json: Parsed Jira response body.
        status_code: HTTP status code returned by Jira.

    Returns:
        Safe issue creation error message for user-facing propagation.
    """
    message_parts = []

    if not isinstance(response_json, dict):
        return f"Failed to create Jira issue: Jira returned status code {status_code}."

    errors = response_json.get("errors")
    if isinstance(errors, dict):
        message_parts.extend(
            f"'{field}': '{message}'" for field, message in errors.items() if message
        )

    error_messages = response_json.get("errorMessages")
    if isinstance(error_messages, list):
        message_parts.extend(str(message) for message in error_messages if message)
    elif isinstance(error_messages, str) and error_messages:
        message_parts.append(error_messages)

    if message_parts:
        return f"Failed to create Jira issue: {'; '.join(message_parts)}"

    return f"Failed to create Jira issue: Jira returned status code {status_code}."


class MarkdownToADFConverter:
    """Helper to convert Markdown strings into Atlassian Document Format blocks."""

    def __init__(self) -> None:
        self._parser = MarkdownIt("commonmark", {"html": False})

    def convert(self, text: Optional[str]) -> List[Dict]:
        if text is None:
            text = ""

        tokens = self._parser.parse(text)
        if not tokens:
            return [self._paragraph_with_text(text)]

        content_stack: List[List[Dict]] = [[]]
        node_stack: List[Dict] = []

        for token in tokens:
            token_type = token.type

            if token_type == "paragraph_open":
                node = {"type": "paragraph", "content": []}
                node_stack.append(node)
                content_stack.append(node["content"])
            elif token_type == "inline":
                inline_nodes = self._convert_inline(token.children or [])
                content_stack[-1].extend(inline_nodes)
            elif token_type == "paragraph_close":
                node = node_stack.pop()
                content_stack.pop()
                content_stack[-1].append(node)
            elif token_type == "bullet_list_open":
                node = {"type": "bulletList", "content": []}
                node_stack.append(node)
                content_stack.append(node["content"])
            elif token_type == "bullet_list_close":
                node = node_stack.pop()
                content_stack.pop()
                content_stack[-1].append(node)
            elif token_type == "ordered_list_open":
                node: Dict = {"type": "orderedList", "content": []}
                start_attr = token.attrGet("start")
                if start_attr and start_attr.isdigit():
                    start = int(start_attr)
                    if start != 1:
                        node["attrs"] = {"order": start}
                node_stack.append(node)
                content_stack.append(node["content"])
            elif token_type == "ordered_list_close":
                node = node_stack.pop()
                content_stack.pop()
                content_stack[-1].append(node)
            elif token_type == "list_item_open":
                node = {"type": "listItem", "content": []}
                node_stack.append(node)
                content_stack.append(node["content"])
            elif token_type == "list_item_close":
                node = node_stack.pop()
                content_stack.pop()
                content_stack[-1].append(node)
            elif token_type == "heading_open":
                level = self._safe_heading_level(token.tag)
                node = {"type": "heading", "attrs": {"level": level}, "content": []}
                node_stack.append(node)
                content_stack.append(node["content"])
            elif token_type == "heading_close":
                node = node_stack.pop()
                content_stack.pop()
                content_stack[-1].append(node)
            elif token_type == "blockquote_open":
                node = {"type": "blockquote", "content": []}
                node_stack.append(node)
                content_stack.append(node["content"])
            elif token_type == "blockquote_close":
                node = node_stack.pop()
                content_stack.pop()
                content_stack[-1].append(node)
            elif token_type in {"fence", "code_block"}:
                language = None
                if token_type == "fence":
                    info = (token.info or "").strip()
                    if info:
                        language = info.split()[0]
                code_text = token.content.rstrip("\n")
                code_node: Dict = {
                    "type": "codeBlock",
                    "content": [self._create_text_node(code_text, None)],
                }
                if language:
                    code_node["attrs"] = {"language": language}
                content_stack[-1].append(code_node)
            elif token_type in {"hr", "thematic_break"}:
                content_stack[-1].append({"type": "rule"})
            elif token_type == "html_block":
                html_text = token.content.strip()
                if html_text:
                    content_stack[-1].append(self._paragraph_with_text(html_text))

        result = content_stack[0]
        if not result:
            return [self._paragraph_with_text(text)]

        return result

    def _convert_inline(self, tokens: List[Token]) -> List[Dict]:
        result: List[Dict] = []
        marks_stack: List[Dict] = []

        for token in tokens:
            token_type = token.type

            if token_type == "text":
                result.extend(self._text_to_nodes(token.content, marks_stack))
            elif token_type == "code_inline":
                marks = self._clone_marks(marks_stack)
                marks.append({"type": "code"})
                result.append(self._create_text_node(token.content, marks))
            elif token_type in {"softbreak", "hardbreak"}:
                result.append({"type": "hardBreak"})
            elif token_type == "strong_open":
                marks_stack.append({"type": "strong"})
            elif token_type == "strong_close":
                self._pop_mark(marks_stack, "strong")
            elif token_type == "em_open":
                marks_stack.append({"type": "em"})
            elif token_type == "em_close":
                self._pop_mark(marks_stack, "em")
            elif token_type == "link_open":
                href = token.attrGet("href") or ""
                mark: Dict = {"type": "link", "attrs": {"href": href}}
                title = token.attrGet("title")
                if title:
                    mark["attrs"]["title"] = title
                marks_stack.append(mark)
            elif token_type == "link_close":
                self._pop_mark(marks_stack, "link")
            elif token_type == "html_inline":
                result.extend(self._text_to_nodes(token.content, marks_stack))
            elif token_type == "image":
                alt_text = token.attrGet("alt") or token.content or ""
                result.extend(self._text_to_nodes(alt_text, marks_stack))

        return result

    @staticmethod
    def _clone_marks(marks_stack: List[Dict]) -> List[Dict]:
        cloned: List[Dict] = []
        for mark in marks_stack:
            mark_copy = {"type": mark["type"]}
            if "attrs" in mark:
                mark_copy["attrs"] = dict(mark["attrs"])
            cloned.append(mark_copy)
        return cloned

    def _text_to_nodes(self, text: str, marks_stack: List[Dict]) -> List[Dict]:
        if not text:
            return []

        nodes: List[Dict] = []
        marks = self._clone_marks(marks_stack)
        parts = text.split("\n")

        for index, part in enumerate(parts):
            if part:
                nodes.append(self._create_text_node(part, marks))
            if index < len(parts) - 1:
                nodes.append({"type": "hardBreak"})

        return nodes

    @staticmethod
    def _create_text_node(text: str, marks: Optional[List[Dict]]) -> Dict:
        node: Dict = {"type": "text", "text": text}
        if marks:
            node["marks"] = marks
        return node

    def _paragraph_with_text(self, text: str) -> Dict:
        # ADF forbids empty text nodes; emit an empty paragraph instead.
        content = [self._create_text_node(text, None)] if text else []
        return {"type": "paragraph", "content": content}

    @staticmethod
    def _pop_mark(marks_stack: List[Dict], mark_type: str) -> None:
        for index in range(len(marks_stack) - 1, -1, -1):
            if marks_stack[index]["type"] == mark_type:
                marks_stack.pop(index)
                break

    @staticmethod
    def _safe_heading_level(tag: Optional[str]) -> int:
        if tag and tag.startswith("h"):
            try:
                level = int(tag[1])
                return max(1, min(level, 6))
            except (ValueError, IndexError):
                return 1
        return 1


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
        - get_available_issue_labels: Get the available labels for a project
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
        - JiraBasicAuthError: Failed to authenticate using basic auth
        - JiraInvalidParameterError: The provided parameters in Init are invalid

    Usage:
        jira = Jira(
            redirect_uri="http://localhost:8080",
            client_id="client_id",
            client_secret="client_secret
        )
        jira.send_findings(findings=findings, project_key="KEY")
    """

    _markdown_converter = MarkdownToADFConverter()
    _redirect_uri: str = None
    _client_id: str = None
    _client_secret: str = None
    _access_token: str = None
    _user_mail: str = None
    _api_token: str = None
    _domain: str = None
    _using_basic_auth: bool = False
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
    REQUEST_TIMEOUT = 90
    HEADER_TEMPLATE = {
        "Content-Type": "application/json",
        "X-Force-Accept-Language": "true",
        "Accept-Language": "en",
    }

    def __init__(
        self,
        redirect_uri: str = None,
        client_id: str = None,
        client_secret: str = None,
        user_mail: str = None,
        api_token: str = None,
        domain: str = None,
    ):
        self._redirect_uri = redirect_uri
        self._client_id = client_id
        self._client_secret = client_secret
        self._user_mail = user_mail
        self._api_token = api_token
        self._domain = domain
        self._scopes = ["read:jira-user", "read:jira-work", "write:jira-work"]
        # If the client mail, API token and site name are present, use basic auth
        if user_mail and api_token and domain:
            self._using_basic_auth = True
            self.get_basic_auth()
        # If the redirect URI, client ID and client secret are present, use auth code flow
        elif redirect_uri and client_id and client_secret:
            auth_url = self.auth_code_url()
            authorization_code = self.input_authorization_code(auth_url)
            self.get_auth(authorization_code)
        else:
            init_error = "Failed to initialize Jira object, missing parameters."
            raise JiraInvalidParameterError(
                message=init_error, file=os.path.basename(__file__)
            )

    @staticmethod
    def _sanitize_summary(summary: str) -> str:
        """Normalize and truncate a Jira issue summary.

        Args:
            summary: Raw summary text.

        Returns:
            The summary collapsed to one line and limited to Jira's 255-character
            summary maximum.
        """
        return " ".join(summary.split())[:255]

    @staticmethod
    def _build_code_block_content(code_value: str) -> Optional[Dict]:
        if not code_value:
            return None

        lines = code_value.splitlines()
        if not lines:
            return None

        language = None
        first_line = lines[0].strip()
        if first_line.startswith("```"):
            language = first_line[3:].strip() or None
            lines = lines[1:]

        while lines and not lines[0].strip():
            lines = lines[1:]

        if lines and lines[-1].strip().startswith("```"):
            lines = lines[:-1]

        while lines and not lines[-1].strip():
            lines = lines[:-1]

        if not lines:
            return None

        sanitized_text = "\n".join(lines)

        code_block: Dict = {
            "type": "codeBlock",
            "content": [{"type": "text", "text": sanitized_text}],
        }

        if language:
            code_block["attrs"] = {"language": language}

        return code_block

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

    @property
    def using_basic_auth(self):
        return self._using_basic_auth

    def get_headers(
        self, access_token: str = None, content_type_json: bool = False
    ) -> dict:
        """Get headers for API requests

        Args:
            access_token: The access token to use for authorization
            content_type_json: Whether to include Content-Type: application/json

        Returns:
            dict: Headers for API requests
        """
        headers = self.HEADER_TEMPLATE.copy()

        if not content_type_json:
            headers.pop("Content-Type", None)

        if access_token:
            if self._using_basic_auth:
                headers["Authorization"] = f"Basic {access_token}"
            else:
                headers["Authorization"] = f"Bearer {access_token}"

        return headers

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

    def get_basic_auth(self) -> None:
        """Get the access token using the mail and API token.

        Returns:
            - None

        Raises:
            - JiraBasicAuthError: Failed to authenticate using basic auth
        """
        try:
            user_string = f"{self._user_mail}:{self._api_token}"
            self._access_token = base64.b64encode(user_string.encode("utf-8")).decode(
                "utf-8"
            )
            self._cloud_id = self.get_cloud_id(self._access_token, domain=self._domain)
        except Exception as e:
            message_error = f"Failed to get auth using basic auth: {e}"
            logger.error(message_error)
            raise JiraBasicAuthError(
                message=message_error,
                file=os.path.basename(__file__),
            )

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

            headers = self.get_headers(content_type_json=True)
            response = requests.post(
                self.TOKEN_URL,
                json=body,
                headers=headers,
                timeout=self.REQUEST_TIMEOUT,
            )

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

    def get_cloud_id(self, access_token: str = None, domain: str = None) -> str:
        """Get the cloud ID from Jira

        Args:
            - access_token: The access token from Jira
            - domain: The site name from Jira

        Returns:
            - str: The cloud ID

        Raises:
            - JiraGetCloudIDNoResourcesError: No resources were found in Jira when getting the cloud id
            - JiraGetCloudIDResponseError: Failed to get the cloud ID, response code did not match 200
            - JiraGetCloudIDError: Failed to get the cloud ID from Jira
        """
        try:
            if self._using_basic_auth:
                if not domain or not ATLASSIAN_SITE_NAME_REGEX.fullmatch(domain):
                    raise ValueError("Invalid Jira site name.")
                headers = self.get_headers(access_token)
                response = requests.get(
                    f"https://{domain}.atlassian.net/_edge/tenant_info",
                    headers=headers,
                    timeout=self.REQUEST_TIMEOUT,
                    allow_redirects=False,
                )
                response = response.json()
                return response.get("cloudId")
            else:
                headers = self.get_headers(access_token)
                response = requests.get(
                    self.API_TOKEN_URL,
                    headers=headers,
                    timeout=self.REQUEST_TIMEOUT,
                )

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
                logger.error(response_error)
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
            # If using basic auth, return the access token
            if self._using_basic_auth:
                return self._access_token

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

            headers = self.get_headers(content_type_json=True)
            response = requests.post(
                url,
                json=body,
                headers=headers,
                timeout=self.REQUEST_TIMEOUT,
            )

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
                logger.error(response_error)
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
        user_mail: str = None,
        api_token: str = None,
        domain: str = None,
        raise_on_exception: bool = True,
    ) -> JiraConnection:
        """Test the connection to Jira

        Args:
            - redirect_uri: The redirect URI
            - client_id: The client ID
            - client_secret: The client secret
            - user_mail: The client mail
            - api_token: The API token
            - domain: The site name
            - raise_on_exception: Whether to raise an exception or not

        Returns:
            - JiraConnection: The connection object

        Raises:
            - JiraGetCloudIDNoResourcesError: No resources were found in Jira when getting the cloud id
            - JiraGetCloudIDResponseError: Failed to get the cloud ID, response code did not match 200
            - JiraGetCloudIDError: Failed to get the cloud ID from Jira
            - JiraAuthenticationError: Failed to authenticate
            - JiraTestConnectionError: Failed to test the connection
            - JiraNoProjectsError: No projects found in Jira
            - JiraGetProjectsResponseError: Failed to get projects from Jira, response code did not match 200
        """
        try:
            jira = Jira(
                redirect_uri=redirect_uri,
                client_id=client_id,
                client_secret=client_secret,
                user_mail=user_mail,
                api_token=api_token,
                domain=domain,
            )
            projects = jira.get_projects()

            issue_types = {}
            for project_key in projects:
                try:
                    issue_types[project_key] = jira.get_available_issue_types(
                        project_key
                    )
                except Exception as e:
                    logger.warning(
                        f"Failed to get issue types for project {project_key}: {e}"
                    )

            return JiraConnection(
                is_connected=True, projects=projects, issue_types=issue_types
            )
        except JiraNoProjectsError as no_projects_error:
            logger.error(
                f"{no_projects_error.__class__.__name__}[{no_projects_error.__traceback__.tb_lineno}]: {no_projects_error}"
            )
            if raise_on_exception:
                raise no_projects_error
            return JiraConnection(error=no_projects_error)
        except JiraGetCloudIDResponseError as response_error:
            logger.error(
                f"{response_error.__class__.__name__}[{response_error.__traceback__.tb_lineno}]: {response_error}"
            )
            if raise_on_exception:
                raise response_error
            return JiraConnection(error=response_error)
        except JiraGetCloudIDError as cloud_id_error:
            logger.error(
                f"{cloud_id_error.__class__.__name__}[{cloud_id_error.__traceback__.tb_lineno}]: {cloud_id_error}"
            )
            if raise_on_exception:
                raise cloud_id_error
            return JiraConnection(error=cloud_id_error)
        except JiraAuthenticationError as auth_error:
            logger.error(
                f"{auth_error.__class__.__name__}[{auth_error.__traceback__.tb_lineno}]: {auth_error}"
            )
            if raise_on_exception:
                raise auth_error
            return JiraConnection(error=auth_error)
        except JiraBasicAuthError as basic_auth_error:
            logger.error(
                f"{basic_auth_error.__class__.__name__}[{basic_auth_error.__traceback__.tb_lineno}]: {basic_auth_error}"
            )
            if raise_on_exception:
                raise basic_auth_error
            return JiraConnection(error=basic_auth_error)
        except JiraGetProjectsResponseError as projects_response_error:
            logger.error(
                f"{projects_response_error.__class__.__name__}[{projects_response_error.__traceback__.tb_lineno}]: {projects_response_error}"
            )
            if raise_on_exception:
                raise projects_response_error
            return JiraConnection(error=projects_response_error)
        except Exception as error:
            logger.error(f"Failed to test connection: {error}")
            if raise_on_exception:
                raise JiraTestConnectionError(
                    message="Failed to test connection on the Jira integration",
                    file=os.path.basename(__file__),
                )
            return JiraConnection(is_connected=False, error=error)

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

            headers = self.get_headers(access_token)

            response = requests.get(
                f"https://api.atlassian.com/ex/jira/{self.cloud_id}/rest/api/3/project",
                headers=headers,
                timeout=self.REQUEST_TIMEOUT,
            )

            if response.status_code == 200:
                # Return the Project Key and Name, using only a dictionary
                projects = {
                    project["key"]: project["name"] for project in response.json()
                }
                if projects == {}:  # If no projects are found
                    logger.error("No projects found")
                    raise JiraNoProjectsError(
                        message="No projects found in Jira",
                        file=os.path.basename(__file__),
                    )
                return projects
            else:
                logger.error(
                    f"Failed to get projects: {response.status_code} - {response.text}"
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

            headers = self.get_headers(access_token)

            response = requests.get(
                f"https://api.atlassian.com/ex/jira/{self.cloud_id}/rest/api/3/issue/createmeta?projectKeys={project_key}&expand=projects.issuetypes.fields",
                headers=headers,
                timeout=self.REQUEST_TIMEOUT,
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
                response_error = f"Failed to get available issue types: {response.status_code} - {response.text}"
                logger.error(response_error)
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

    def get_metadata(self) -> dict:
        """Get the metadata from Jira

        Returns:
            - dict: The projects and issue types from Jira as a dictionary, the projects format is {"KEY": {"name": "NAME", "issue_types": ["ISSUE_TYPE_1", "ISSUE_TYPE_2"]}}
        """
        try:
            access_token = self.get_access_token()

            if not access_token:
                return ValueError("Failed to get access token")

            headers = self.get_headers(access_token)

            response = requests.get(
                f"https://api.atlassian.com/ex/jira/{self.cloud_id}/rest/api/3/project",
                headers=headers,
                timeout=self.REQUEST_TIMEOUT,
            )
            if response.status_code == 200:
                projects_data = {}
                projects_list = response.json()
                if not projects_list:
                    logger.error("No projects found")
                    raise JiraNoProjectsError(
                        message="No projects found in Jira",
                        file=os.path.basename(__file__),
                    )
                else:
                    for project in projects_list:
                        project_response = requests.get(
                            f"https://api.atlassian.com/ex/jira/{self.cloud_id}/rest/api/3/issue/createmeta?projectKeys={project['key']}&expand=projects.issuetypes.fields",
                            headers=headers,
                            timeout=self.REQUEST_TIMEOUT,
                        )
                        if project_response.status_code == 200:
                            project_metadata = project_response.json()
                            if len(project_metadata["projects"]) == 0:
                                logger.error(
                                    f"No project metadata found for project {project['key']}, setting empty issue types"
                                )
                                issue_types = []
                            else:
                                issue_types = [
                                    issue_type["name"]
                                    for issue_type in project_metadata["projects"][0][
                                        "issuetypes"
                                    ]
                                ]
                        else:
                            raise JiraGetAvailableIssueTypesResponseError(
                                message="Failed to get available issue types from Jira",
                                file=os.path.basename(__file__),
                            )
                        projects_data[project["key"]] = {
                            "name": project["name"],
                            "issue_types": issue_types,
                        }
                    return projects_data
            else:
                logger.error(
                    f"Failed to get projects: {response.status_code} - {response.text}"
                )
                raise JiraGetProjectsResponseError(
                    message="Failed to get projects from Jira",
                    file=os.path.basename(__file__),
                )
        except JiraNoProjectsError as no_projects_error:
            raise no_projects_error
        except JiraGetAvailableIssueTypesResponseError as issue_types_error:
            raise JiraGetProjectsError(
                message=f"Failed to get projects and issue types from Jira: {issue_types_error}",
                file=os.path.basename(__file__),
            )
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
        if status == "MANUAL":
            return "#FFFF00"
        return "#000000"

    @staticmethod
    def get_severity_color(severity: str) -> str:
        """Get the color from the severity

        Args:
            - severity: The severity of the finding

        Returns:
            - str: The color of the severity
        """
        if severity == "critical":
            return "#FF0000"
        if severity == "high":
            return "#FFA500"
        if severity == "medium":
            return "#FFFF00"
        if severity == "low":
            return "#008000"
        if severity == "informational":
            return "#0000FF"
        return "#000000"  # Default black color for unknown severities

    @staticmethod
    def _adf_colored_strong_marks(color_mark_type: str, color: str) -> list[dict]:
        """Build ADF marks for bold text with a Jira color mark.

        Args:
            color_mark_type: Jira ADF color mark type, such as textColor or
                backgroundColor.
            color: Hex color value for the mark.

        Returns:
            ADF marks for strong colored text.
        """
        return [
            {"type": "strong"},
            {"type": color_mark_type, "attrs": {"color": color}},
        ]

    def _adf_severity_marks(
        self, severity: str = "", severity_color: str | None = None
    ) -> list[dict]:
        """Build ADF marks for severity text.

        Args:
            severity: Finding severity used to derive a color when severity_color
                is not provided.
            severity_color: Optional explicit severity color.

        Returns:
            ADF marks for highlighted severity text.
        """
        color = severity_color or self.get_severity_color(str(severity).lower())
        return self._adf_colored_strong_marks("backgroundColor", color)

    def _adf_status_marks(
        self, status: str = "", status_color: str | None = None
    ) -> list[dict]:
        """Build ADF marks for status text.

        Args:
            status: Finding status used to derive a color when status_color is
                not provided.
            status_color: Optional explicit status color.

        Returns:
            ADF marks for colored status text.
        """
        color = status_color or self.get_color_from_status(str(status).upper())
        return self._adf_colored_strong_marks("textColor", color)

    @staticmethod
    def _adf_text_node(text: str, marks: list[dict] | None = None) -> dict:
        """Build an ADF text node.

        Args:
            text: Text content for the node.
            marks: Optional ADF marks to apply to the text.

        Returns:
            ADF text node with optional marks.
        """
        node = {"type": "text", "text": text}
        if marks:
            node["marks"] = marks
        return node

    def _adf_severity_text_node(
        self, severity: str = "", severity_color: str | None = None
    ) -> dict:
        """Build an ADF text node for severity.

        Args:
            severity: Severity text to render.
            severity_color: Optional explicit severity color.

        Returns:
            ADF text node with severity marks.
        """
        return self._adf_text_node(
            severity, self._adf_severity_marks(severity, severity_color)
        )

    def _adf_status_text_node(
        self, status: str = "", status_color: str | None = None
    ) -> dict:
        """Build an ADF text node for status.

        Args:
            status: Status text to render.
            status_color: Optional explicit status color.

        Returns:
            ADF text node with status marks.
        """
        return self._adf_text_node(status, self._adf_status_marks(status, status_color))

    def get_adf_description(
        self,
        check_id: str = "",
        check_title: str = "",
        severity: str = "",
        severity_color: str = "",
        status: str = "",
        status_color: str = "",
        status_extended: str = "",
        provider: str = "",
        region: str = "",
        resource_uid: str = "",
        resource_name: str = "",
        risk: str = "",
        recommendation_text: str = "",
        recommendation_url: str = "",
        remediation_code_native_iac: str = "",
        remediation_code_terraform: str = "",
        remediation_code_cli: str = "",
        remediation_code_other: str = "",
        resource_tags: dict = "",
        compliance: dict = "",
        finding_url: str = "",
        tenant_info: str = "",
    ) -> dict:

        # ADF forbids empty text nodes, so Jira rejects them with 400 INVALID_INPUT.
        def _safe(value: str) -> str:
            return value if (value and value.strip()) else "-"

        check_id = _safe(check_id)
        check_title = _safe(check_title)
        status_extended = _safe(status_extended)
        provider = _safe(provider)
        region = _safe(region)
        resource_uid = _safe(resource_uid)
        resource_name = _safe(resource_name)

        table_rows = [
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
                                    self._adf_severity_text_node(
                                        severity, severity_color
                                    )
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
                                    self._adf_status_text_node(status, status_color)
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
                        "content": self._markdown_converter.convert(risk),
                    },
                ],
            },
        ]

        # Add resource tags row only if there are tags
        if resource_tags:
            tags_text = ", ".join([f"{k}={v}" for k, v in resource_tags.items()])
            table_rows.append(
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
                                            "text": "Resource Tags",
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
                                            "text": tags_text,
                                            "marks": [{"type": "code"}],
                                        }
                                    ],
                                }
                            ],
                        },
                    ],
                }
            )

        # Add compliance row only if there are compliance mappings
        if compliance:
            compliance_text = []
            for framework, requirements in compliance.items():
                if requirements:
                    requirements_str = ", ".join(requirements)
                    compliance_text.append(f"{framework}: {requirements_str}")

            if compliance_text:
                table_rows.append(
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
                                                "text": "Compliance",
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
                                                "text": "; ".join(compliance_text),
                                                "marks": [{"type": "code"}],
                                            }
                                        ],
                                    }
                                ],
                            },
                        ],
                    }
                )

        # Add recommendation row
        recommendation_content = self._markdown_converter.convert(recommendation_text)
        if recommendation_url:
            link_node = {
                "type": "text",
                "text": recommendation_url,
                "marks": [{"type": "link", "attrs": {"href": recommendation_url}}],
            }

            if (
                recommendation_content
                and recommendation_content[-1].get("type") == "paragraph"
            ):
                paragraph = recommendation_content[-1]
                paragraph_content = paragraph.setdefault("content", [])
                if paragraph_content:
                    last_inline = paragraph_content[-1]
                    if last_inline.get("type") == "text" and not last_inline.get(
                        "text", ""
                    ).endswith(" "):
                        paragraph_content.append({"type": "text", "text": " "})
                    elif last_inline.get("type") != "text":
                        paragraph_content.append({"type": "text", "text": " "})
                paragraph_content.append(link_node)
            else:
                recommendation_content.append(
                    {"type": "paragraph", "content": [link_node]}
                )

        table_rows.append(
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
                        "content": recommendation_content,
                    },
                ],
            }
        )

        # Add remediation code rows only if they have content
        remediation_codes = [
            ("Native IaC", remediation_code_native_iac),
            ("Terraform", remediation_code_terraform),
            ("CLI", remediation_code_cli),
            ("Other", remediation_code_other),
        ]

        for code_type, code_value in remediation_codes:
            if code_value and code_value.strip():
                if code_type == "Other":
                    formatted_content = self._markdown_converter.convert(code_value)
                else:
                    code_block = self._build_code_block_content(code_value)
                    if not code_block:
                        continue
                    formatted_content = [code_block]

                table_rows.append(
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
                                                "text": f"Remediation {code_type}",
                                                "marks": [{"type": "strong"}],
                                            }
                                        ],
                                    }
                                ],
                            },
                            {
                                "type": "tableCell",
                                "attrs": {"colwidth": [3]},
                                "content": formatted_content,
                            },
                        ],
                    }
                )

        if finding_url:
            table_rows.append(
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
                                            "text": "Finding URL",
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
                                            "text": finding_url,
                                            "marks": [
                                                {
                                                    "type": "link",
                                                    "attrs": {"href": finding_url},
                                                }
                                            ],
                                        }
                                    ],
                                }
                            ],
                        },
                    ],
                }
            )

        if tenant_info:
            table_rows.append(
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
                                            "text": "Tenant Info",
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
                                            "text": tenant_info,
                                            "marks": [{"type": "code"}],
                                        }
                                    ],
                                }
                            ],
                        },
                    ],
                }
            )

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
                    "content": table_rows,
                },
            ],
        }

    def get_grouped_adf_description(
        self,
        check_id: str = "",
        check_title: str = "",
        check_description: str = "",
        severity: str = "",
        status: str = "",
        provider: str = "",
        service: str = "",
        affected_failing_resources: int = 0,
        last_seen: str = "",
        failing_for: str = "",
        grouped_resources: list[dict] | None = None,
        resources_total: int = 0,
        resources_shown: int = 0,
        finding_group_url: str = "",
        finding_group_link_text: str = "",
        risk: str = "",
        recommendation_text: str = "",
        recommendation_url: str = "",
    ) -> dict:
        """Build a Jira ADF description for a grouped finding issue.

        Args:
            check_id: Finding check ID.
            check_title: Finding check title.
            check_description: Finding check description.
            severity: Finding group severity.
            status: Finding group status.
            provider: Cloud provider name.
            service: Provider service name.
            affected_failing_resources: Number of failing resources in the group.
            last_seen: Last time the finding group was seen.
            failing_for: Duration the finding group has been failing.
            grouped_resources: Resource rows to include in the grouped issue.
            resources_total: Total number of resources in the group.
            resources_shown: Number of resources rendered in this Jira issue.
            finding_group_url: Optional URL for the full finding group.
            finding_group_link_text: Optional link text for finding_group_url.
            risk: Risk description for the check.
            recommendation_text: Remediation recommendation text.
            recommendation_url: Optional remediation recommendation URL.

        Returns:
            Jira ADF document describing the finding group.
        """

        def _safe(value) -> str:
            return str(value) if value not in (None, "") else "-"

        def _text(value, marks: list[dict] | None = None) -> dict:
            node = {"type": "text", "text": _safe(value)}
            if marks:
                node["marks"] = marks
            return node

        def _paragraph(value, marks: list[dict] | None = None) -> dict:
            return {"type": "paragraph", "content": [_text(value, marks)]}

        def _cell(value, marks: list[dict] | None = None) -> dict:
            return {"type": "tableCell", "content": [_paragraph(value, marks)]}

        def _content_cell(content: list[dict]) -> dict:
            return {"type": "tableCell", "content": content}

        def _append_link(content: list[dict], url: str) -> list[dict]:
            if not url:
                return content

            link_node = {
                "type": "text",
                "text": url,
                "marks": [{"type": "link", "attrs": {"href": url}}],
            }
            if content and content[-1].get("type") == "paragraph":
                paragraph_content = content[-1].setdefault("content", [])
                if paragraph_content:
                    last_inline = paragraph_content[-1]
                    if last_inline.get("type") != "text" or not last_inline.get(
                        "text", ""
                    ).endswith(" "):
                        paragraph_content.append({"type": "text", "text": " "})
                paragraph_content.append(link_node)
            else:
                content.append({"type": "paragraph", "content": [link_node]})
            return content

        def _row(cells: list[dict]) -> dict:
            return {"type": "tableRow", "content": cells}

        strong = [{"type": "strong"}]
        code = [{"type": "code"}]
        severity_marks = self._adf_severity_marks(severity)
        status_marks = self._adf_status_marks(status)
        recommendation_content = _append_link(
            self._markdown_converter.convert(_safe(recommendation_text)),
            recommendation_url,
        )
        main_rows = [
            _row([_cell("Check Id", strong), _cell(check_id, code)]),
            _row([_cell("Check Title", strong), _cell(check_title)]),
            _row([_cell("Severity", strong), _cell(severity, severity_marks)]),
            _row([_cell("Status", strong), _cell(status, status_marks)]),
            _row([_cell("Provider", strong), _cell(provider, code)]),
            _row([_cell("Service", strong), _cell(service, code)]),
            _row(
                [
                    _cell("Affected Failing Resources", strong),
                    _cell(affected_failing_resources, strong),
                ]
            ),
            _row([_cell("Last Seen", strong), _cell(last_seen)]),
            _row([_cell("Failing For", strong), _cell(failing_for)]),
            _row(
                [
                    _cell("Risk", strong),
                    _content_cell(self._markdown_converter.convert(_safe(risk))),
                ]
            ),
            _row(
                [
                    _cell("Recommendation", strong),
                    _content_cell(recommendation_content),
                ]
            ),
        ]

        resource_rows = [
            _row(
                [
                    _cell("Resource", strong),
                    _cell("Resource UID", strong),
                    _cell("Provider", strong),
                    _cell("Service", strong),
                    _cell("Account / Tenant", strong),
                    _cell("Status", strong),
                    _cell("Severity", strong),
                    _cell("Region", strong),
                    _cell("Last Seen", strong),
                    _cell("Failing For", strong),
                    _cell("Triage", strong),
                ]
            )
        ]
        for resource in grouped_resources or []:
            resource_status = resource.get("status")
            resource_severity = str(resource.get("severity", "")).upper()
            resource_status_marks = self._adf_status_marks(resource_status)
            resource_severity_marks = self._adf_severity_marks(resource_severity)
            resource_rows.append(
                _row(
                    [
                        _cell(resource.get("resource_name"), code),
                        _cell(resource.get("resource_uid"), code),
                        _cell(resource.get("provider"), code),
                        _cell(resource.get("service"), code),
                        _cell(resource.get("provider_account"), code),
                        _cell(resource_status, resource_status_marks),
                        _cell(resource_severity, resource_severity_marks),
                        _cell(resource.get("region"), code),
                        _cell(resource.get("last_seen")),
                        _cell(resource.get("failing_for")),
                        _cell(resource.get("triage")),
                    ]
                )
            )

        content = [
            _paragraph("Prowler has discovered the following Finding Group:"),
            {"type": "table", "attrs": {"layout": "full-width"}, "content": main_rows},
        ]

        content.extend(
            [
                {
                    "type": "heading",
                    "attrs": {"level": 2},
                    "content": [_text("Affected failing resources")],
                },
                {
                    "type": "table",
                    "attrs": {"layout": "full-width"},
                    "content": resource_rows,
                },
            ]
        )

        if resources_total > resources_shown:
            remaining_content = [
                _text(f"Showing {resources_shown} of {resources_total} Findings.")
            ]
            if finding_group_url and finding_group_link_text:
                remaining_content = [
                    _text(
                        f"Showing {resources_shown} of {resources_total} Findings "
                        "in this Jira issue. "
                    ),
                    _text(
                        finding_group_link_text,
                        [
                            {
                                "type": "link",
                                "attrs": {"href": finding_group_url},
                            }
                        ],
                    ),
                ]
            content.append(
                {
                    "type": "paragraph",
                    "content": remaining_content,
                }
            )
        elif finding_group_url and finding_group_link_text:
            content.append(
                {
                    "type": "paragraph",
                    "content": [
                        _text(
                            finding_group_link_text,
                            [
                                {
                                    "type": "link",
                                    "attrs": {"href": finding_group_url},
                                }
                            ],
                        ),
                    ],
                }
            )

        return {"type": "doc", "version": 1, "content": content}

    def send_findings(
        self,
        findings: list[Finding] = None,
        project_key: str = None,
        issue_type: str = None,
        issue_labels: list[str] = None,
        finding_url: str = None,
        tenant_info: str = None,
    ):
        """
        Send the findings to Jira

        Args:
            - findings: The findings to send
            - project_key: The project key
            - issue_type: The issue type
            - issue_labels: The issue labels
            - finding_url: The finding URL
            - tenant_info: The tenant info

        Raises:
            - JiraRefreshTokenError: Failed to refresh the access token
            - JiraRefreshTokenResponseError: Failed to refresh the access token, response code did not match 200
            - JiraCreateIssueError: Failed to create an issue in Jira
            - JiraSendFindingsResponseError: Failed to send the findings to Jira
            - JiraRequiredCustomFieldsError: Jira project requires custom fields that are not supported
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

            headers = self.get_headers(access_token, content_type_json=True)

            for finding in findings:
                status_color = self.get_color_from_status(finding.status.value)
                severity_color = self.get_severity_color(
                    finding.metadata.Severity.value.lower()
                )
                adf_description = self.get_adf_description(
                    check_id=finding.metadata.CheckID,
                    check_title=finding.metadata.CheckTitle,
                    severity=finding.metadata.Severity.value.upper(),
                    severity_color=severity_color,
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
                    remediation_code_native_iac=finding.metadata.Remediation.Code.NativeIaC,
                    remediation_code_terraform=finding.metadata.Remediation.Code.Terraform,
                    remediation_code_cli=finding.metadata.Remediation.Code.CLI,
                    remediation_code_other=finding.metadata.Remediation.Code.Other,
                    resource_tags=finding.resource_tags,
                    compliance=finding.compliance,
                    finding_url=finding_url,
                    tenant_info=tenant_info,
                )
                summary_parts = ["[Prowler]"]
                if finding.metadata.Severity.value:
                    summary_parts.append(finding.metadata.Severity.value.upper())
                if finding.metadata.CheckID:
                    summary_parts.append(finding.metadata.CheckID)
                if finding.resource_uid:
                    summary_parts.append(finding.resource_uid)

                summary = " - ".join(summary_parts[1:])
                summary = self._sanitize_summary(f"{summary_parts[0]} {summary}")

                payload = {
                    "fields": {
                        "project": {"key": project_key},
                        "summary": summary,
                        "description": adf_description,
                        "issuetype": {"name": issue_type},
                        "customfield_10148": {"value": "SDK"},
                        "customfield_10088": {"value": "Core"},
                    }
                }
                if issue_labels:
                    payload["fields"]["labels"] = issue_labels

                response = requests.post(
                    f"https://api.atlassian.com/ex/jira/{self.cloud_id}/rest/api/3/issue",
                    json=payload,
                    headers=headers,
                    timeout=self.REQUEST_TIMEOUT,
                )

                if response.status_code != 201:
                    try:
                        response_json = response.json()
                    except (ValueError, requests.exceptions.JSONDecodeError):
                        response_error = f"Failed to send finding: {response.status_code} - {response.text}"
                        logger.error(response_error)
                        raise JiraSendFindingsResponseError(
                            message=response_error, file=os.path.basename(__file__)
                        )

                    # Check if the error is due to required custom fields
                    if response.status_code == 400 and "errors" in response_json:
                        errors = response_json.get("errors", {})
                        # Look for custom field errors (fields starting with "customfield_")
                        custom_field_errors = {
                            k: v
                            for k, v in errors.items()
                            if k.startswith("customfield_")
                        }
                        if custom_field_errors:
                            custom_fields_formatted = ", ".join(
                                [
                                    f"'{k}': '{v}'"
                                    for k, v in custom_field_errors.items()
                                ]
                            )
                            raise JiraRequiredCustomFieldsError(
                                message=f"Jira project requires custom fields that are not supported: {custom_fields_formatted}",
                                file=os.path.basename(__file__),
                            )

                    response_error = f"Failed to send finding: {response.status_code} - {response_json}"
                    logger.error(response_error)
                    raise JiraSendFindingsResponseError(
                        message=response_error, file=os.path.basename(__file__)
                    )
                else:
                    try:
                        response_json = response.json()
                        logger.info(f"Finding sent successfully: {response_json}")
                    except (ValueError, requests.exceptions.JSONDecodeError):
                        logger.info(
                            f"Finding sent successfully: Status {response.status_code}"
                        )
        except JiraRequiredCustomFieldsError as custom_fields_error:
            raise custom_fields_error
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

    def send_finding(
        self,
        check_id: str = "",
        check_title: str = "",
        check_description: str = "",
        severity: str = "",
        status: str = "",
        status_extended: str = "",
        provider: str = "",
        region: str = "",
        service: str = "",
        resource_uid: str = "",
        resource_name: str = "",
        risk: str = "",
        recommendation_text: str = "",
        recommendation_url: str = "",
        remediation_code_native_iac: str = "",
        remediation_code_terraform: str = "",
        remediation_code_cli: str = "",
        remediation_code_other: str = "",
        resource_tags: dict = "",
        compliance: dict = "",
        project_key: str = "",
        issue_type: str = "",
        issue_labels: list[str] = "",
        finding_url: str = "",
        tenant_info: str = "",
        affected_failing_resources: int = 0,
        grouped_resources: list[dict] | None = None,
        resources_total: int = 0,
        resources_shown: int = 0,
        last_seen: str = "",
        failing_for: str = "",
        finding_group_url: str = "",
        finding_group_link_text: str = "",
    ) -> bool:
        """
        Send the finding to Jira

        Args:
            - check_id: The check ID
            - check_title: The check title
            - check_description: The check description
            - severity: The severity
            - status: The status
            - status_extended: The status extended
            - provider: The provider
            - region: The region
            - service: The service
            - resource_uid: The resource UID
            - resource_name: The resource name
            - risk: The risk
            - recommendation_text: The recommendation text
            - recommendation_url: The recommendation URL
            - remediation_code_native_iac: The remediation code native IAC
            - remediation_code_terraform: The remediation code terraform
            - remediation_code_cli: The remediation code CLI
            - remediation_code_other: The remediation code other
            - resource_tags: The resource tags
            - compliance: The compliance
            - project_key: The project key
            - issue_type: The issue type
            - issue_labels: The issue labels
            - finding_url: The finding URL
            - tenant_info: The tenant info
            - affected_failing_resources: The number of affected failing resources
            - grouped_resources: The grouped resources to render, or None for a
              single finding issue
            - resources_total: The total resources in the finding group
            - resources_shown: The resources shown in the Jira issue
            - last_seen: The last time the finding group was seen
            - failing_for: The duration the finding group has been failing
            - finding_group_url: The finding group URL
            - finding_group_link_text: The link text for the finding group URL

        Raises:
            - JiraRefreshTokenError: Failed to refresh the access token
            - JiraRefreshTokenResponseError: Failed to refresh the access token, response code did not match 200
            - JiraNoTokenError: Failed to get an access token
            - JiraCreateIssueError: Failed to create an issue in Jira
            - JiraSendFindingsResponseError: Failed to send the finding to Jira
            - JiraRequiredCustomFieldsError: Jira project requires custom fields that are not supported

        Returns:
            - True if the finding was sent successfully
            - False if the finding was not sent successfully
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

            headers = self.get_headers(access_token, content_type_json=True)

            status_color = self.get_color_from_status(status)
            severity_color = self.get_severity_color(severity.lower())
            if grouped_resources is not None:
                adf_description = self.get_grouped_adf_description(
                    check_id=check_id,
                    check_title=check_title,
                    check_description=check_description,
                    severity=severity.upper(),
                    status=status,
                    provider=provider,
                    service=service,
                    affected_failing_resources=affected_failing_resources,
                    last_seen=last_seen,
                    failing_for=failing_for,
                    grouped_resources=grouped_resources,
                    resources_total=resources_total,
                    resources_shown=resources_shown,
                    finding_group_url=finding_group_url,
                    finding_group_link_text=finding_group_link_text,
                    risk=risk,
                    recommendation_text=recommendation_text,
                    recommendation_url=recommendation_url,
                )
            else:
                adf_description = self.get_adf_description(
                    check_id=check_id,
                    check_title=check_title,
                    severity=severity.upper(),
                    severity_color=severity_color,
                    status=status,
                    status_color=status_color,
                    status_extended=status_extended,
                    provider=provider,
                    region=region,
                    resource_uid=resource_uid,
                    resource_name=resource_name,
                    risk=risk,
                    recommendation_text=recommendation_text,
                    recommendation_url=recommendation_url,
                    remediation_code_native_iac=remediation_code_native_iac,
                    remediation_code_terraform=remediation_code_terraform,
                    remediation_code_cli=remediation_code_cli,
                    remediation_code_other=remediation_code_other,
                    resource_tags=resource_tags,
                    compliance=compliance,
                    finding_url=finding_url,
                    tenant_info=tenant_info,
                )

            summary_parts = ["[Prowler]"]
            if severity:
                summary_parts.append(severity.upper())
            if check_id:
                summary_parts.append(check_id)
            if grouped_resources is not None:
                summary_parts.append(
                    f"{affected_failing_resources} affected failing resources"
                )
            elif resource_uid:
                summary_parts.append(resource_uid)
            summary = " - ".join(summary_parts[1:])
            summary = self._sanitize_summary(f"{summary_parts[0]} {summary}")

            payload = {
                "fields": {
                    "project": {"key": project_key},
                    "summary": summary,
                    "description": adf_description,
                    "issuetype": {"name": issue_type},
                }
            }
            if issue_labels:
                payload["fields"]["labels"] = issue_labels

            response = requests.post(
                f"https://api.atlassian.com/ex/jira/{self.cloud_id}/rest/api/3/issue",
                json=payload,
                headers=headers,
                timeout=self.REQUEST_TIMEOUT,
            )

            if response.status_code != 201:
                try:
                    response_json = response.json()
                except (ValueError, requests.exceptions.JSONDecodeError):
                    response_error = _format_jira_issue_creation_error(
                        {}, response.status_code
                    )
                    logger.error(response_error)
                    raise JiraSendFindingsResponseError(
                        message=response_error, file=os.path.basename(__file__)
                    )

                # Check if the error is due to required custom fields
                if (
                    response.status_code == 400
                    and isinstance(response_json, dict)
                    and "errors" in response_json
                ):
                    errors = response_json.get("errors", {})
                    # Look for custom field errors (fields starting with "customfield_")
                    custom_field_errors = {}
                    if isinstance(errors, dict):
                        custom_field_errors = {
                            k: v
                            for k, v in errors.items()
                            if k.startswith("customfield_")
                        }
                    if custom_field_errors:
                        custom_fields_formatted = ", ".join(
                            [f"'{k}': '{v}'" for k, v in custom_field_errors.items()]
                        )
                        raise JiraRequiredCustomFieldsError(
                            message=f"Jira project requires custom fields that are not supported: {custom_fields_formatted}",
                            file=os.path.basename(__file__),
                        )

                response_error = _format_jira_issue_creation_error(
                    response_json, response.status_code
                )
                logger.error(response_error)
                raise JiraSendFindingsResponseError(
                    message=response_error, file=os.path.basename(__file__)
                )
            else:
                try:
                    response_json = response.json()
                    logger.info(f"Finding sent successfully: {response_json}")
                except (ValueError, requests.exceptions.JSONDecodeError):
                    logger.info(
                        f"Finding sent successfully: Status {response.status_code}"
                    )
                return True
        except JiraRequiredCustomFieldsError as custom_fields_error:
            logger.error(f"Custom fields error: {custom_fields_error}")
            raise custom_fields_error
        except JiraSendFindingsResponseError as response_error:
            logger.error(f"Jira response error: {response_error}")
            raise response_error
        except JiraRefreshTokenError as refresh_error:
            logger.error(f"Token refresh error: {refresh_error}")
            raise refresh_error
        except JiraRefreshTokenResponseError as response_error:
            raise response_error
        except JiraNoTokenError as no_token_error:
            raise no_token_error
        except Exception as e:
            logger.error(f"Failed to send finding: {e}")
            return False
