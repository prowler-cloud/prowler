import base64
import hashlib
import hmac
import json
from datetime import datetime
from email.utils import formatdate
from threading import Lock
from typing import Optional

import requests
from alibabacloud_tea_openapi import models as open_api_models
from alibabacloud_tea_util import models as util_models
from defusedxml import ElementTree
from pydantic.v1 import BaseModel

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.alibabacloud.lib.service.service import AlibabaCloudService


class OSS(AlibabaCloudService):
    """
    OSS (Object Storage Service) service class for Alibaba Cloud.

    This class provides methods to interact with Alibaba Cloud OSS service
    to retrieve buckets, ACLs, and policies.
    """

    def __init__(self, provider):
        # Call AlibabaCloudService's __init__
        # Treat as regional for client generation consistency with other services
        super().__init__(__class__.__name__, provider, global_service=False)
        self._buckets_lock = Lock()
        self._bucket_inventory_lock = Lock()
        self._bucket_inventory_loaded = False

        # Fetch OSS resources
        self.buckets = {}
        self.__threading_call__(self._list_buckets)
        self.__threading_call__(self._get_bucket_acl, self.buckets.values())
        self.__threading_call__(self._get_bucket_policy, self.buckets.values())
        self.__threading_call__(self._get_bucket_logging, self.buckets.values())

    def _list_buckets(self, regional_client=None):
        region = "unknown"
        try:
            with self._bucket_inventory_lock:
                if self._bucket_inventory_loaded:
                    return
                self._bucket_inventory_loaded = True

            regional_client = regional_client or self.client
            region = getattr(regional_client, "region", self.region)
            endpoint = f"oss-{region}.aliyuncs.com"
            endpoint_label = f"region {region}"

            credentials = self.session.get_credentials()

            date_str = formatdate(usegmt=True)
            headers = {
                "Date": date_str,
                "Host": endpoint,
            }
            canonical_headers = []
            if credentials.security_token:
                headers["x-oss-security-token"] = credentials.security_token
                canonical_headers.append(
                    f"x-oss-security-token:{credentials.security_token}"
                )

            canonical_headers_str = ""
            if canonical_headers:
                canonical_headers.sort()
                canonical_headers_str = "\n".join(canonical_headers) + "\n"

            string_to_sign = f"GET\n\n\n{date_str}\n{canonical_headers_str}/"
            signature = base64.b64encode(
                hmac.new(
                    credentials.access_key_secret.encode("utf-8"),
                    string_to_sign.encode("utf-8"),
                    hashlib.sha1,
                ).digest()
            ).decode()
            headers["Authorization"] = f"OSS {credentials.access_key_id}:{signature}"

            url = f"https://{endpoint}/"
            response = self._call_with_retries(
                requests.get, url, headers=headers, timeout=10
            )
            if response.status_code != 200:
                if response.status_code == 403 and "UserDisable" in (
                    response.text or ""
                ):
                    logger.info(
                        f"OSS - HTTP listing {endpoint_label} skipped because OSS is disabled for this account."
                    )
                else:
                    logger.error(
                        f"OSS - HTTP listing {endpoint_label} returned {response.status_code}: {response.text}"
                    )
                return

            try:
                xml_root = ElementTree.fromstring(response.text)
            except ElementTree.ParseError as error:
                logger.error(
                    f"OSS - HTTP listing {endpoint_label} XML parse error: {error}"
                )
                return

            for bucket_elem in xml_root.findall(".//Bucket"):
                bucket_name = bucket_elem.findtext("Name", default="")
                if not bucket_name:
                    continue
                location = bucket_elem.findtext("Location", default=self.region)
                arn = f"acs:oss::{self.audited_account}:{bucket_name}"
                if self.audit_resources and not is_resource_filtered(
                    arn, self.audit_resources
                ):
                    continue

                creation_str = bucket_elem.findtext("CreationDate")
                with self._buckets_lock:
                    self.buckets[arn] = Bucket(
                        arn=arn,
                        name=bucket_name,
                        region=self._normalize_bucket_region(location),
                        creation_date=self._parse_creation_date(creation_str),
                    )
        except Exception as error:
            logger.error(
                f"{region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            return

    def _get_bucket_subresource(self, bucket, action: str, subresource: str) -> dict:
        """Call a bucket sub-resource API (GET /?<subresource>) and return its parsed body.

        The generated OSS SDK methods return empty response models for these
        APIs: the OSS gateway keeps the XML root element when it deserializes
        the body, while the generated response models expect its children at the
        top level. Calling the shared ``execute`` path directly and unwrapping the
        root element preserves the actual configuration.

        Args:
            bucket: Bucket to query.
            action: OSS API action name (e.g. ``GetBucketLogging``).
            subresource: Sub-resource query string (e.g. ``logging``).

        Returns:
            dict: Content of the XML root element, or an empty dict when the
            response carries no configuration.

        Raises:
            Exception: Any error raised by the OSS SDK, including ``TeaException``
            with the OSS error code for 4xx/5xx responses.
        """
        oss_client = self.session.client("oss", bucket.region)
        params = open_api_models.Params(
            action=action,
            version="2019-05-17",
            protocol="HTTPS",
            pathname=f"/?{subresource}",
            method="GET",
            auth_type="AK",
            style="ROA",
            req_body_type="xml",
            body_type="xml",
        )
        request = open_api_models.OpenApiRequest(
            host_map={"bucket": bucket.name}, headers={}
        )
        response = oss_client.execute(params, request, util_models.RuntimeOptions())
        body = response.get("body") if isinstance(response, dict) else None
        if not isinstance(body, dict):
            return {}
        if len(body) == 1:
            root_content = next(iter(body.values()))
            return root_content if isinstance(root_content, dict) else {}
        return body

    def _get_bucket_acl(self, bucket):
        """Get bucket ACL (private, public-read or public-read-write)."""
        logger.info(f"OSS - Getting ACL for bucket {bucket.name}...")
        try:
            acl_policy = self._get_bucket_subresource(bucket, "GetBucketAcl", "acl")
            grant = (acl_policy.get("AccessControlList") or {}).get("Grant")
            bucket.acl = str(grant) if grant else "private"
        except Exception as error:
            logger.error(
                f"{bucket.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _get_bucket_policy(self, bucket):
        """Get bucket policy."""
        logger.info(f"OSS - Getting policy for bucket {bucket.name}...")
        try:
            oss_client = self.session.client("oss", bucket.region)

            response = oss_client.get_bucket_policy(bucket.name)

            if response and response.body:
                if response.body:
                    try:
                        bucket.policy = json.loads(response.body)
                    except json.JSONDecodeError:
                        bucket.policy = {}
                else:
                    bucket.policy = {}
            else:
                bucket.policy = {}

        except Exception as error:
            # If bucket policy doesn't exist, that's OK - it means no public access via policy
            error_code = getattr(error, "code", "")
            if error_code in ["NoSuchBucketPolicy", "NoSuchBucket"]:
                bucket.policy = {}
            else:
                logger.error(
                    f"{bucket.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
                bucket.policy = {}

    def _get_bucket_logging(self, bucket):
        """Get bucket logging configuration."""
        logger.info(f"OSS - Getting logging configuration for bucket {bucket.name}...")
        try:
            logging_status = self._get_bucket_subresource(
                bucket, "GetBucketLogging", "logging"
            )
            logging_enabled = logging_status.get("LoggingEnabled") or {}
            target_bucket = logging_enabled.get("TargetBucket")
            if target_bucket:
                bucket.logging_enabled = True
                bucket.logging_target_bucket = str(target_bucket)
                bucket.logging_target_prefix = str(
                    logging_enabled.get("TargetPrefix") or ""
                )
            else:
                bucket.logging_enabled = False
                bucket.logging_target_bucket = ""
                bucket.logging_target_prefix = ""
        except Exception as error:
            logger.error(
                f"{bucket.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    @staticmethod
    def _normalize_bucket_region(bucket_location: str) -> str:
        """Normalize OSS bucket location values to region IDs."""
        if not bucket_location:
            return ""

        normalized_location = bucket_location.lower()

        # Remove protocol/hostname suffix if an endpoint was returned
        if ".aliyuncs.com" in normalized_location:
            normalized_location = normalized_location.split(".aliyuncs.com")[0]

        # Strip leading OSS prefix (e.g., oss-ap-southeast-1 -> ap-southeast-1)
        if normalized_location.startswith("oss-"):
            normalized_location = normalized_location.replace("oss-", "", 1)

        return normalized_location

    @staticmethod
    def _parse_creation_date(creation_date_str: Optional[str]) -> Optional[datetime]:
        """Parse OSS bucket creation date strings into datetime objects."""
        if not creation_date_str:
            return None

        for date_format in ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z"):
            try:
                return datetime.strptime(
                    creation_date_str.replace("Z", "+00:00"), date_format
                )
            except (ValueError, AttributeError):
                continue
        return None


class Bucket(BaseModel):
    """OSS Bucket model."""

    arn: str
    name: str
    region: str
    acl: Optional[str] = None  # private, public-read, public-read-write
    policy: dict = {}
    logging_enabled: bool = False
    logging_target_bucket: str = ""
    logging_target_prefix: str = ""
    creation_date: Optional[datetime] = None
