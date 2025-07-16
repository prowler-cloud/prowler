import time
from threading import current_thread
from typing import Any, Dict, List, Optional

import requests
from requests.auth import HTTPDigestAuth

from prowler.lib.logger import logger
from prowler.providers.mongodbatlas.exceptions.exceptions import (
    MongoDBAtlasAPIError,
    MongoDBAtlasRateLimitError,
)


class MongoDBAtlasService:
    """Base class for MongoDB Atlas services"""

    def __init__(self, service_name: str, provider):
        self.service_name = service_name
        self.provider = provider
        self.session = provider.session
        self.base_url = provider.session.base_url
        self.auth = HTTPDigestAuth(
            provider.session.public_key, provider.session.private_key
        )
        self.headers = {
            "Accept": "application/vnd.atlas.2025-01-01+json",
            "Content-Type": "application/json",
        }

    def _make_request(
        self,
        method: str,
        endpoint: str,
        params: Optional[Dict] = None,
        data: Optional[Dict] = None,
        max_retries: int = 3,
        retry_delay: int = 1,
    ) -> Dict[str, Any]:
        """
        Make HTTP request to MongoDB Atlas API with retry logic

        Args:
            method: HTTP method (GET, POST, PUT, DELETE)
            endpoint: API endpoint (without base URL)
            params: Query parameters
            data: Request body data
            max_retries: Maximum number of retries
            retry_delay: Delay between retries in seconds

        Returns:
            dict: Response JSON data

        Raises:
            MongoDBAtlasAPIError: If the API request fails
            MongoDBAtlasRateLimitError: If rate limit is exceeded
        """
        url = f"{self.base_url}/{endpoint.lstrip('/')}"

        for attempt in range(max_retries + 1):
            try:
                response = requests.request(
                    method=method,
                    url=url,
                    auth=self.auth,
                    headers=self.headers,
                    params=params,
                    json=data,
                    timeout=30,
                )

                if response.status_code == 429:
                    if attempt < max_retries:
                        logger.warning(
                            f"Rate limit exceeded for {url}, retrying in {retry_delay} seconds..."
                        )
                        time.sleep(retry_delay)
                        retry_delay *= 2
                        continue
                    else:
                        raise MongoDBAtlasRateLimitError(
                            message=f"Rate limit exceeded for {url} after {max_retries} retries"
                        )

                response.raise_for_status()
                return response.json()

            except requests.exceptions.RequestException as e:
                if attempt < max_retries:
                    logger.warning(
                        f"Request failed for {url}, retrying in {retry_delay} seconds: {str(e)}"
                    )
                    time.sleep(retry_delay)
                    retry_delay *= 2
                    continue
                else:
                    logger.error(
                        f"Request failed for {url} after {max_retries} retries: {str(e)}"
                    )
                    raise MongoDBAtlasAPIError(
                        original_exception=e,
                        message=f"Failed to make request to {url}: {str(e)}",
                    )

    def _paginate_request(
        self,
        endpoint: str,
        params: Optional[Dict] = None,
        page_size: int = 100,
        max_pages: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        """
        Make paginated requests to MongoDB Atlas API

        Args:
            endpoint: API endpoint
            params: Query parameters
            page_size: Number of items per page
            max_pages: Maximum number of pages to fetch

        Returns:
            list: List of all items from all pages
        """
        if params is None:
            params = {}

        params.update({"pageNum": 1, "itemsPerPage": page_size})

        all_items = []
        page_num = 1

        while True:
            params["pageNum"] = page_num

            try:
                response = self._make_request("GET", endpoint, params=params)

                if "results" in response:
                    items = response["results"]
                    all_items.extend(items)

                    total_count = response.get("totalCount", 0)

                    if len(items) < page_size or len(all_items) >= total_count:
                        break

                    if max_pages and page_num >= max_pages:
                        logger.warning(
                            f"Reached maximum pages limit ({max_pages}) for {endpoint}"
                        )
                        break

                    page_num += 1
                else:
                    break

            except Exception as e:
                logger.error(
                    f"Error during pagination for {endpoint} at page {page_num}: {str(e)}"
                )
                break

        logger.info(
            f"Retrieved {len(all_items)} items from {endpoint} across {page_num} pages"
        )

        return all_items

    def _get_thread_info(self) -> str:
        """Get thread information for logging"""
        return f"[{current_thread().name}]"
