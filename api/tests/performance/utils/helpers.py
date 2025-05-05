import random
from collections import defaultdict
from threading import Lock

import requests
from locust import HttpUser, between
from utils.config import (
    BASE_HEADERS,
    FINDINGS_RESOURCE_METADATA,
    TARGET_INSERTED_AT,
    USER_EMAIL,
    USER_PASSWORD,
)

_global_page_counters = defaultdict(int)
_page_lock = Lock()


class APIUserBase(HttpUser):
    """
    Base class for API user simulation in Locust performance tests.

    Attributes:
        abstract (bool): Indicates this is an abstract user class.
        wait_time: Time between task executions, randomized between 1 and 5 seconds.
    """

    abstract = True
    wait_time = between(1, 5)

    def _next_page(self, endpoint_name: str) -> int:
        """
        Returns the next page number for a given endpoint. Thread-safe.

        Args:
            endpoint_name (str): Name of the API endpoint being paginated.

        Returns:
            int: The next page number for the given endpoint.
        """
        with _page_lock:
            _global_page_counters[endpoint_name] += 1
            return _global_page_counters[endpoint_name]


def get_next_resource_filter(available_values: dict) -> tuple:
    """
    Randomly selects a filter type and value from available options.

    Args:
        available_values (dict): Dictionary with filter types as keys and list of possible values.

    Returns:
        tuple: A (filter_type, filter_value) pair randomly selected.
    """
    filter_type = random.choice(list(available_values.keys()))
    filter_value = random.choice(available_values[filter_type])
    return filter_type, filter_value


def get_auth_headers(token: str) -> dict:
    """
    Returns the headers for the API requests.

    Args:
        token (str): The token to be included in the headers.

    Returns:
        dict: The headers for the API requests.
    """
    return {
        "Authorization": f"Bearer {token}",
        **BASE_HEADERS,
    }


def get_api_token(host: str) -> str:
    """
    Authenticates with the API and retrieves a bearer token.

    Args:
        host (str): The host URL of the API.

    Returns:
        str: The access token for authenticated requests.

    Raises:
        AssertionError: If the request fails or does not return a 200 status code.
    """
    login_payload = {
        "data": {
            "type": "tokens",
            "attributes": {"email": USER_EMAIL, "password": USER_PASSWORD},
        }
    }
    response = requests.post(f"{host}/tokens", json=login_payload, headers=BASE_HEADERS)
    assert response.status_code == 200, f"Failed to get token: {response.text}"
    return response.json()["data"]["attributes"]["access"]


def get_scan_id_from_provider_name(host: str, token: str, provider_name: str) -> str:
    """
    Retrieves the scan ID associated with a specific provider name.

    Args:
        host (str): The host URL of the API.
        token (str): Bearer token for authentication.
        provider_name (str): Name of the provider to filter scans by.

    Returns:
        str: The ID of the scan.

    Raises:
        AssertionError: If the request fails or does not return a 200 status code.
    """
    response = requests.get(
        f"{host}/scans?fields[scans]=id&filter[provider_alias]={provider_name}",
        headers=get_auth_headers(token),
    )
    assert response.status_code == 200, f"Failed to get scan: {response.text}"
    return response.json()["data"][0]["id"]


def get_resource_filters_pairs(host: str, token: str, scan_id: str = "") -> dict:
    """
    Retrieves and maps resource metadata filter values from the findings endpoint.

    Args:
        host (str): The host URL of the API.
        token (str): Bearer token for authentication.
        scan_id (str, optional): Optional scan ID to filter metadata. Defaults to using inserted_at timestamp.

    Returns:
        dict: A dictionary of resource filter metadata.

    Raises:
        AssertionError: If the request fails or does not return a 200 status code.
    """
    metadata_filters = (
        f"filter[scan]={scan_id}"
        if scan_id
        else f"filter[inserted_at]={TARGET_INSERTED_AT}"
    )
    response = requests.get(
        f"{host}/findings/metadata?{metadata_filters}", headers=get_auth_headers(token)
    )
    assert (
        response.status_code == 200
    ), f"Failed to get resource filters values: {response.text}"
    attributes = response.json()["data"]["attributes"]
    return {
        FINDINGS_RESOURCE_METADATA[key]: values
        for key, values in attributes.items()
        if key in FINDINGS_RESOURCE_METADATA.keys()
    }


def get_sort_value(sort_values: list) -> str:
    """
    Constructs a sort query string from a list of sort keys.

    Args:
        sort_values (list): The list of sort values to include in the query.

    Returns:
        str: A formatted sort query string (e.g., "sort=created_at,-severity").
    """
    return f"sort={','.join(sort_values)}"
