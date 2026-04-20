import base64
import json
from dataclasses import dataclass
from datetime import date, datetime
from typing import List, Optional

import requests
import urllib3

from prowler.lib.integrations.elasticsearch.exceptions.exceptions import (
    ElasticsearchConnectionError,
    ElasticsearchIndexError,
)
from prowler.lib.logger import logger

# Disable SSL warnings when skip_tls_verify is True
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Maximum number of findings to send in a single bulk request
ELASTICSEARCH_MAX_BATCH = 500


def _json_serial(obj):
    """JSON serializer for objects not serializable by default json code."""
    if isinstance(obj, (datetime, date)):
        return obj.isoformat()
    if isinstance(obj, set):
        return list(obj)
    raise TypeError(f"Object of type {type(obj).__name__} is not JSON serializable")


@dataclass
class ElasticsearchConnection:
    """Elasticsearch connection status."""

    connected: bool = False
    error_message: str = ""
    index_exists: bool = False


class Elasticsearch:
    """Elasticsearch integration for sending OCSF findings."""

    def __init__(
        self,
        url: str,
        index: str,
        api_key: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        skip_tls_verify: bool = False,
        findings: List[dict] = None,
        send_only_fails: bool = False,
    ):
        """
        Initialize the Elasticsearch integration.

        Args:
            url: Elasticsearch server URL (e.g., https://localhost:9200)
            index: Elasticsearch index name
            api_key: Elasticsearch API key for authentication
            username: Elasticsearch username for basic auth
            password: Elasticsearch password for basic auth
            skip_tls_verify: Skip TLS certificate verification
            findings: List of OCSF findings to send
            send_only_fails: Only send failed findings
        """
        self._url = url.rstrip("/") if url else ""
        self._index = index
        self._api_key = api_key
        self._username = username
        self._password = password
        self._skip_tls_verify = skip_tls_verify
        self._send_only_fails = send_only_fails
        self._findings = self._filter_findings(findings or [])
        self._session = self._create_session()

    def _create_session(self) -> requests.Session:
        """Create HTTP session with authentication."""
        session = requests.Session()

        # Set authentication headers
        if self._api_key:
            session.headers["Authorization"] = f"ApiKey {self._api_key}"
        elif self._username and self._password:
            credentials = base64.b64encode(
                f"{self._username}:{self._password}".encode()
            ).decode()
            session.headers["Authorization"] = f"Basic {credentials}"

        session.headers["Content-Type"] = "application/json"

        # Configure TLS verification
        session.verify = not self._skip_tls_verify

        return session

    def _filter_findings(self, findings: List[dict]) -> List[dict]:
        """Filter findings based on status if send_only_fails is True."""
        if self._send_only_fails:
            return [f for f in findings if f.get("status_code") == "FAIL"]
        return findings

    def test_connection(self) -> ElasticsearchConnection:
        """
        Test connection to Elasticsearch cluster.

        Returns:
            ElasticsearchConnection with connection status
        """
        connection = ElasticsearchConnection()

        try:
            response = self._session.get(
                f"{self._url}/",
                timeout=30,
            )

            if response.status_code == 200:
                connection.connected = True
                logger.info(f"Successfully connected to Elasticsearch at {self._url}")
            elif response.status_code == 401:
                connection.error_message = (
                    "Authentication failed. Check your credentials."
                )
                logger.error(
                    f"Elasticsearch authentication failed at {self._url}: {response.text}"
                )
            else:
                connection.error_message = (
                    f"Unexpected response: {response.status_code} - {response.text}"
                )
                logger.error(
                    f"Elasticsearch connection error at {self._url}: {response.status_code}"
                )

        except requests.exceptions.SSLError as e:
            connection.error_message = f"SSL/TLS error. Use --elasticsearch-skip-tls-verify if using self-signed certificates: {str(e)}"
            logger.error(f"Elasticsearch SSL error: {e}")
        except requests.exceptions.ConnectionError as e:
            connection.error_message = f"Could not connect to server: {str(e)}"
            logger.error(f"Elasticsearch connection error: {e}")
        except requests.exceptions.Timeout as e:
            connection.error_message = f"Connection timed out: {str(e)}"
            logger.error(f"Elasticsearch timeout: {e}")
        except Exception as e:
            connection.error_message = f"Unexpected error: {str(e)}"
            logger.error(f"Elasticsearch unexpected error: {e}")

        return connection

    def create_index_if_not_exists(self) -> bool:
        """
        Create index with OCSF-compatible mapping if it doesn't exist.

        Returns:
            True if index exists or was created successfully
        """
        try:
            # Check if index exists
            response = self._session.head(
                f"{self._url}/{self._index}",
                timeout=30,
            )

            if response.status_code == 200:
                logger.info(f"Elasticsearch index '{self._index}' already exists")
                return True

            # Create index with dynamic mapping for OCSF data
            # Using dynamic mapping to accommodate the full OCSF schema
            index_settings = {
                "settings": {
                    "number_of_shards": 1,
                    "number_of_replicas": 0,
                    "index.mapping.total_fields.limit": 2000,
                },
                "mappings": {
                    "dynamic": True,
                    "properties": {
                        "time": {"type": "date", "format": "epoch_second"},
                        "time_dt": {"type": "date"},
                        "severity_id": {"type": "integer"},
                        "severity": {"type": "keyword"},
                        "status_id": {"type": "integer"},
                        "status": {"type": "keyword"},
                        "status_code": {"type": "keyword"},
                        "activity_id": {"type": "integer"},
                        "activity_name": {"type": "keyword"},
                        "type_uid": {"type": "integer"},
                        "type_name": {"type": "keyword"},
                        "category_uid": {"type": "integer"},
                        "category_name": {"type": "keyword"},
                        "class_uid": {"type": "integer"},
                        "class_name": {"type": "keyword"},
                        "message": {"type": "text"},
                        "status_detail": {"type": "text"},
                        "risk_details": {"type": "text"},
                        "finding_info": {
                            "properties": {
                                "uid": {"type": "keyword"},
                                "title": {
                                    "type": "text",
                                    "fields": {"keyword": {"type": "keyword"}},
                                },
                                "desc": {"type": "text"},
                                "created_time": {
                                    "type": "date",
                                    "format": "epoch_second",
                                },
                                "created_time_dt": {"type": "date"},
                                "types": {"type": "keyword"},
                                "name": {"type": "keyword"},
                            }
                        },
                        "cloud": {
                            "properties": {
                                "provider": {"type": "keyword"},
                                "region": {"type": "keyword"},
                                "account": {
                                    "properties": {
                                        "uid": {"type": "keyword"},
                                        "name": {"type": "keyword"},
                                        "type_id": {"type": "integer"},
                                        "type": {"type": "keyword"},
                                    }
                                },
                                "org": {
                                    "properties": {
                                        "uid": {"type": "keyword"},
                                        "name": {"type": "keyword"},
                                    }
                                },
                            }
                        },
                        "resources": {
                            "type": "nested",
                            "properties": {
                                "uid": {"type": "keyword"},
                                "name": {"type": "keyword"},
                                "type": {"type": "keyword"},
                                "region": {"type": "keyword"},
                                "cloud_partition": {"type": "keyword"},
                                "namespace": {"type": "keyword"},
                                "labels": {"type": "keyword"},
                                "group": {
                                    "properties": {
                                        "name": {"type": "keyword"},
                                    }
                                },
                            },
                        },
                        "metadata": {
                            "properties": {
                                "event_code": {"type": "keyword"},
                                "version": {"type": "keyword"},
                                "profiles": {"type": "keyword"},
                                "tenant_uid": {"type": "keyword"},
                                "product": {
                                    "properties": {
                                        "uid": {"type": "keyword"},
                                        "name": {"type": "keyword"},
                                        "vendor_name": {"type": "keyword"},
                                        "version": {"type": "keyword"},
                                    }
                                },
                            }
                        },
                        "remediation": {
                            "properties": {
                                "desc": {"type": "text"},
                                "references": {"type": "keyword"},
                            }
                        },
                    },
                },
            }

            response = self._session.put(
                f"{self._url}/{self._index}",
                json=index_settings,
                timeout=30,
            )

            if response.status_code in (200, 201):
                logger.info(f"Created Elasticsearch index '{self._index}'")
                return True
            else:
                logger.error(
                    f"Failed to create index '{self._index}': {response.status_code} - {response.text}"
                )
                return False

        except Exception as e:
            logger.error(f"Error creating Elasticsearch index: {e}")
            raise ElasticsearchIndexError(
                index=self._index,
                message=str(e),
                original_exception=e,
            )

    def batch_send_to_elasticsearch(self) -> int:
        """
        Send findings to Elasticsearch using bulk API.

        Returns:
            Number of findings successfully sent
        """
        if not self._findings:
            logger.info("No findings to send to Elasticsearch")
            return 0

        total_sent = 0

        try:
            total_sent = self._send_findings_in_batches(self._findings)
            logger.info(f"Sent {total_sent} findings to Elasticsearch")
        except Exception as e:
            logger.error(f"Error sending findings to Elasticsearch: {e}")
            raise

        return total_sent

    def _send_findings_in_batches(self, findings: List[dict]) -> int:
        """
        Send findings in batches using the bulk API.

        Args:
            findings: List of OCSF findings to send

        Returns:
            Number of findings successfully sent
        """
        total_sent = 0

        # Process findings in batches
        for i in range(0, len(findings), ELASTICSEARCH_MAX_BATCH):
            batch = findings[i : i + ELASTICSEARCH_MAX_BATCH]

            # Build bulk request body
            bulk_body = ""
            for finding in batch:
                # Use finding_info.uid as the document ID if available
                doc_id = finding.get("finding_info", {}).get("uid", None)
                if doc_id:
                    action = {"index": {"_index": self._index, "_id": doc_id}}
                else:
                    action = {"index": {"_index": self._index}}
                bulk_body += json.dumps(action) + "\n"
                bulk_body += json.dumps(finding, default=_json_serial) + "\n"

            try:
                response = self._session.post(
                    f"{self._url}/_bulk",
                    data=bulk_body,
                    headers={"Content-Type": "application/x-ndjson"},
                    timeout=60,
                )

                if response.status_code in (200, 201):
                    result = response.json()
                    if result.get("errors"):
                        # Count successful items
                        success_count = sum(
                            1
                            for item in result.get("items", [])
                            if item.get("index", {}).get("status") in (200, 201)
                        )
                        failed_count = len(batch) - success_count
                        logger.warning(
                            f"Bulk request completed with {failed_count} errors"
                        )
                        total_sent += success_count
                    else:
                        total_sent += len(batch)
                else:
                    logger.error(
                        f"Bulk request failed: {response.status_code} - {response.text}"
                    )

            except Exception as e:
                logger.error(f"Error in bulk request: {e}")
                raise ElasticsearchConnectionError(
                    url=self._url,
                    message=f"Bulk request failed: {str(e)}",
                    original_exception=e,
                )

        return total_sent
