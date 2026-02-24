from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

from prowler.lib.logger import logger
from prowler.providers.googleworkspace.googleworkspace_provider import (
    GoogleworkspaceProvider,
)


class GoogleWorkspaceService:
    def __init__(
        self,
        provider: GoogleworkspaceProvider,
    ):
        self.provider = provider
        self.audit_config = provider.audit_config
        self.fixer_config = provider.fixer_config
        self.credentials = provider.session.credentials

    def _build_service(self, api_name: str, api_version: str):
        """
        Build and return a Google API service client.

        Args:
            api_name: The name of the API (e.g., 'admin')
            api_version: The API version (e.g., 'directory_v1')

        Returns:
            A Google API service client
        """
        try:
            return build(
                api_name,
                api_version,
                credentials=self.credentials,
                cache_discovery=False,
            )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            return None

    def _handle_api_error(self, error, context: str, resource_name: str = ""):
        """
        Centralized Google Workspace API error handling.

        Args:
            error: The exception that was raised
            context: Description of what operation was being performed
            resource_name: Name of the resource being accessed (optional)
        """
        resource_info = resource_name if resource_name else ""

        if isinstance(error, HttpError):
            if error.resp.status == 403:
                logger.error(
                    f"Access denied while {context} {resource_info}: Insufficient permissions or API not enabled"
                )
            elif error.resp.status == 404:
                logger.error(f"{resource_info} not found while {context}")
            elif error.resp.status == 429:
                logger.error(
                    f"Rate limit exceeded while {context} {resource_info}: {error}"
                )
            elif error.resp.status == 401:
                logger.error(
                    f"Authentication error while {context} {resource_info}: Check credentials and delegation"
                )
            else:
                logger.error(
                    f"Google API error ({error.resp.status}) while {context} {resource_info}: {error}"
                )
        else:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] while {context} {resource_info}: {error}"
            )
