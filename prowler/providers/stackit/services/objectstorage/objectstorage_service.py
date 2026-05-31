from datetime import datetime, timezone
from typing import Optional

from pydantic.v1 import BaseModel

from prowler.lib.logger import logger
from prowler.providers.stackit.stackit_provider import StackitProvider, suppress_stderr


class ObjectStorageService:
    def __init__(self, provider: StackitProvider):
        self.provider = provider
        self.project_id = provider.identity.project_id
        self.regional_clients = provider.generate_regional_clients("objectstorage")

        self.buckets: list[Bucket] = []
        self.access_keys: list[AccessKey] = []

        self._fetch_all_regions()

    def _fetch_all_regions(self):
        for region, client in self.regional_clients.items():
            try:
                self._list_buckets(client, region)
                self._list_access_keys(client, region)
            except Exception as error:
                if getattr(error, "status", None) == 404:
                    logger.info(
                        f"StackIT project {self.project_id} has no ObjectStorage "
                        f"presence in region {region}; skipping."
                    )
                    continue
                raise

    def _handle_api_call(self, api_function, *args, **kwargs):
        try:
            with suppress_stderr():
                return api_function(*args, **kwargs)
        except Exception as e:
            self.provider.handle_api_error(e)
            raise

    def _list_buckets(self, client, region: str):
        response = self._handle_api_call(
            client.list_buckets, project_id=self.project_id, region=region
        )

        buckets_list = getattr(response, "buckets", None) or []
        if isinstance(response, dict):
            buckets_list = response.get("buckets", [])

        for bucket_data in buckets_list:
            try:
                if hasattr(bucket_data, "name"):
                    name = bucket_data.name
                    object_lock_enabled = getattr(
                        bucket_data, "object_lock_enabled", False
                    )
                elif isinstance(bucket_data, dict):
                    name = bucket_data.get("name", "")
                    object_lock_enabled = bucket_data.get("objectLockEnabled", False)
                else:
                    continue

                retention_days, retention_mode = self._get_default_retention(
                    client, region, name
                )

                self.buckets.append(
                    Bucket(
                        name=name,
                        region=region,
                        project_id=self.project_id,
                        object_lock_enabled=object_lock_enabled,
                        retention_days=retention_days,
                        retention_mode=retention_mode,
                    )
                )
            except Exception as e:
                logger.error(f"Error processing bucket: {e}")
                continue

        logger.info(f"Listed {len(buckets_list)} buckets in {region}")

    def _get_default_retention(
        self, client, region: str, bucket_name: str
    ) -> tuple[Optional[int], Optional[str]]:
        try:
            response = self._handle_api_call(
                client.get_default_retention,
                project_id=self.project_id,
                region=region,
                bucket_name=bucket_name,
            )
            days = getattr(response, "days", None)
            mode = getattr(response, "mode", None)
            if isinstance(response, dict):
                days = response.get("days")
                mode = response.get("mode")
            return days, str(mode) if mode else None
        except Exception as e:
            if getattr(e, "status", None) == 404:
                return None, None
            raise

    def _list_access_keys(self, client, region: str):
        response = self._handle_api_call(
            client.list_access_keys, project_id=self.project_id, region=region
        )

        keys_list = getattr(response, "access_keys", None) or []
        if isinstance(response, dict):
            keys_list = response.get("accessKeys", [])

        for key_data in keys_list:
            try:
                if hasattr(key_data, "key_id"):
                    key_id = key_data.key_id
                    display_name = getattr(key_data, "display_name", key_id)
                    expires = getattr(key_data, "expires", None)
                elif isinstance(key_data, dict):
                    key_id = key_data.get("keyId", "")
                    display_name = key_data.get("displayName", key_id)
                    expires = key_data.get("expires")
                else:
                    continue

                self.access_keys.append(
                    AccessKey(
                        key_id=key_id,
                        display_name=display_name,
                        expires=expires,
                        region=region,
                        project_id=self.project_id,
                    )
                )
            except Exception as e:
                logger.error(f"Error processing access key: {e}")
                continue

        logger.info(f"Listed {len(keys_list)} access keys in {region}")


class Bucket(BaseModel):
    name: str
    region: str
    project_id: str
    object_lock_enabled: bool = False
    retention_days: Optional[int] = None
    retention_mode: Optional[str] = None


class AccessKey(BaseModel):
    key_id: str
    display_name: str
    # None or a sentinel year-0001 date string means the key never expires.
    expires: Optional[str] = None
    region: str
    project_id: str

    def has_expiration(self) -> bool:
        """Return True if the key has a real (non-sentinel) expiration date."""
        if not self.expires:
            return False
        try:
            expires_str = self.expires.replace("Z", "+00:00")
            dt = datetime.fromisoformat(expires_str)
            # Year 0001 (or earlier) is the SDK sentinel for "never expires"
            return dt.year > 1
        except (ValueError, AttributeError):
            return False

    def expires_within_days(self, days: int) -> bool:
        """Return True if the key expires within the given number of days from now."""
        if not self.has_expiration():
            return False
        try:
            expires_str = self.expires.replace("Z", "+00:00")
            dt = datetime.fromisoformat(expires_str)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            delta = dt - datetime.now(tz=timezone.utc)
            return delta.days <= days
        except (ValueError, AttributeError):
            return False
