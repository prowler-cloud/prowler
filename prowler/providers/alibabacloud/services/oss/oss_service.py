import base64
import hashlib
import hmac
import json
from datetime import datetime
from email.utils import formatdate
from threading import Lock
from typing import Optional
from xml.etree import ElementTree

import requests
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

        # Fetch OSS resources
        self.buckets = {}
        self.__threading_call__(self._list_buckets)
        self.__threading_call__(self._get_bucket_acl, self.buckets.values())
        self.__threading_call__(self._get_bucket_policy, self.buckets.values())
        self.__threading_call__(self._get_bucket_logging, self.buckets.values())

    def _list_buckets(self, regional_client=None):
        region = "unknown"
        try:
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
            response = requests.get(url, headers=headers, timeout=10)
            if response.status_code != 200:
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

    def _get_bucket_acl(self, bucket):
        """Get bucket ACL."""
        logger.info(f"OSS - Getting ACL for bucket {bucket.name}...")
        try:
            # Get OSS client for the bucket's region
            # OSS bucket operations use regional endpoint: oss-{region}.aliyuncs.com
            oss_client = self.session.client("oss", bucket.region)

            # Get bucket ACL
            response = oss_client.get_bucket_acl(bucket.name)

            if response and response.body:
                # ACL can be retrieved from the response
                # The ACL value is typically in the response body
                acl_value = getattr(response.body, "acl", None)
                if acl_value:
                    # ACL values: private, public-read, public-read-write
                    bucket.acl = acl_value
                else:
                    # Try to get from access_control_list if available
                    acl_list = getattr(response.body, "access_control_list", None)
                    if acl_list:
                        grant = getattr(acl_list, "grant", None)
                        if grant:
                            # Check grants to determine ACL type
                            if isinstance(grant, list):
                                # Check if any grant has public access
                                for g in grant:
                                    permission = getattr(g, "permission", "")
                                    if permission in ["READ", "FULL_CONTROL"]:
                                        if permission == "READ":
                                            bucket.acl = "public-read"
                                        else:
                                            bucket.acl = "public-read-write"
                                        break
                                else:
                                    bucket.acl = "private"
                            else:
                                permission = getattr(grant, "permission", "")
                                if permission == "READ":
                                    bucket.acl = "public-read"
                                elif permission == "FULL_CONTROL":
                                    bucket.acl = "public-read-write"
                                else:
                                    bucket.acl = "private"
                        else:
                            bucket.acl = "private"
                    else:
                        bucket.acl = "private"
            else:
                bucket.acl = "private"

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
        """Get bucket logging configuration using OSS SDK."""
        logger.info(f"OSS - Getting logging configuration for bucket {bucket.name}...")
        try:
            oss_client = self.session.client("oss", bucket.region)

            response = oss_client.get_bucket_logging(bucket.name)

            if response and response.body:
                logging_enabled = None
                if hasattr(response.body, "logging_enabled"):
                    logging_enabled = response.body.logging_enabled
                elif hasattr(response.body, "loggingenabled"):
                    logging_enabled = response.body.loggingenabled
                elif hasattr(response.body, "bucket_logging"):
                    logging_enabled = response.body.bucket_logging

                if logging_enabled:
                    target_bucket = None
                    target_prefix = None

                    for attr_name in [
                        "target_bucket",
                        "targetBucket",
                        "target_bucket_name",
                        "targetBucketName",
                    ]:
                        if hasattr(logging_enabled, attr_name):
                            target_bucket = getattr(logging_enabled, attr_name)
                            break

                    for attr_name in [
                        "target_prefix",
                        "targetPrefix",
                        "target_prefix_name",
                        "targetPrefixName",
                    ]:
                        if hasattr(logging_enabled, attr_name):
                            target_prefix = getattr(logging_enabled, attr_name)
                            break

                    if target_bucket:
                        bucket.logging_enabled = True
                        bucket.logging_target_bucket = (
                            str(target_bucket) if target_bucket else ""
                        )
                        bucket.logging_target_prefix = (
                            str(target_prefix) if target_prefix else ""
                        )
                    else:
                        bucket.logging_enabled = False
                        bucket.logging_target_bucket = ""
                        bucket.logging_target_prefix = ""
                else:
                    bucket.logging_enabled = False
                    bucket.logging_target_bucket = ""
                    bucket.logging_target_prefix = ""
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
