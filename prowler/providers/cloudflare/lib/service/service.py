import requests
from colorama import Fore, Style

from prowler.lib.logger import logger


class CloudflareService:
    """
    Base class for Cloudflare services

    This class provides common functionality for all Cloudflare services,
    including API client setup and error handling.
    """

    def __init__(self, service_name: str, provider):
        """
        Initialize CloudflareService

        Args:
            service_name (str): Name of the service
            provider: Cloudflare provider instance
        """
        self.service = service_name
        self.provider = provider
        self.session = provider.session
        self.api_base_url = "https://api.cloudflare.com/client/v4"
        self.headers = self._get_headers()

    def _get_headers(self) -> dict:
        """
        Returns HTTP headers for Cloudflare API requests.

        Returns:
            dict: Headers dictionary with authentication credentials.
        """
        headers = {"Content-Type": "application/json"}

        if self.session.api_token:
            headers["Authorization"] = f"Bearer {self.session.api_token}"
        elif self.session.api_key and self.session.api_email:
            headers["X-Auth-Key"] = self.session.api_key
            headers["X-Auth-Email"] = self.session.api_email

        return headers

    def _api_request(
        self, method: str, endpoint: str, params: dict = None, json_data: dict = None
    ) -> dict:
        """
        Make an API request to Cloudflare

        Args:
            method (str): HTTP method (GET, POST, PUT, DELETE)
            endpoint (str): API endpoint (e.g., "/accounts")
            params (dict): Query parameters
            json_data (dict): JSON data for POST/PUT requests

        Returns:
            dict: API response data

        Raises:
            Exception: If the API request fails
        """
        url = f"{self.api_base_url}{endpoint}"

        try:
            response = requests.request(
                method=method,
                url=url,
                headers=self.headers,
                params=params,
                json=json_data,
                timeout=30,
            )

            response.raise_for_status()
            data = response.json()

            if not data.get("success"):
                errors = data.get("errors", [])
                logger.error(
                    f"{Fore.RED}Cloudflare API Error:{Style.RESET_ALL} {errors}"
                )
                return {}

            return data.get("result", {})

        except requests.exceptions.RequestException as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            return {}

    def _api_request_paginated(
        self, endpoint: str, params: dict = None, page_size: int = 50
    ) -> list:
        """
        Make a paginated API request to Cloudflare

        Args:
            endpoint (str): API endpoint
            params (dict): Query parameters
            page_size (int): Number of results per page

        Returns:
            list: Combined results from all pages
        """
        all_results = []
        page = 1

        if params is None:
            params = {}

        params["per_page"] = page_size

        while True:
            params["page"] = page
            url = f"{self.api_base_url}{endpoint}"

            try:
                response = requests.get(
                    url, headers=self.headers, params=params, timeout=30
                )
                response.raise_for_status()
                data = response.json()

                if not data.get("success"):
                    break

                result = data.get("result", [])
                if not result:
                    break

                all_results.extend(result)

                # Check if there are more pages
                result_info = data.get("result_info", {})
                if page >= result_info.get("total_pages", 0):
                    break

                page += 1

            except requests.exceptions.RequestException as error:
                logger.error(
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
                break

        return all_results

    def _handle_cloudflare_api_error(
        self, error: Exception, action: str, resource: str = ""
    ):
        """
        Handle Cloudflare API errors with consistent logging

        Args:
            error (Exception): The exception that occurred
            action (str): Description of the action being performed
            resource (str): The resource being accessed
        """
        error_message = f"Error {action}"
        if resource:
            error_message += f" for {resource}"
        error_message += f": {error}"

        logger.error(
            f"{Fore.RED}{error_message}{Style.RESET_ALL} ({error.__class__.__name__})"
        )
