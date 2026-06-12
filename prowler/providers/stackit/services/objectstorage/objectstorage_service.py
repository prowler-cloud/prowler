import json
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
            except Exception as e:
                logger.error(f"Error processing bucket: {e}")
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
        credentials_groups_response = self._handle_api_call(
            client.list_credentials_groups, project_id=self.project_id, region=region
        )

        credentials_groups = (
            getattr(credentials_groups_response, "credentials_groups", None) or []
        )
        if isinstance(credentials_groups_response, dict):
            credentials_groups = credentials_groups_response.get(
                "credentialsGroups",
                credentials_groups_response.get("credentials_groups", []),
            )

        total_keys = 0

        for credentials_group_data in credentials_groups:
            try:
                if isinstance(credentials_group_data, dict):
                    credentials_group_id = credentials_group_data.get(
                        "id",
                        credentials_group_data.get(
                            "groupId",
                            credentials_group_data.get("credentialsGroupId", ""),
                        ),
                    )
                    credentials_group_name = credentials_group_data.get(
                        "displayName",
                        credentials_group_data.get("name", credentials_group_id),
                    )
                else:
                    credentials_group_id = (
                        getattr(credentials_group_data, "id", None)
                        or getattr(credentials_group_data, "group_id", None)
                        or getattr(credentials_group_data, "credentials_group_id", "")
                    )
                    credentials_group_name = getattr(
                        credentials_group_data,
                        "display_name",
                        getattr(credentials_group_data, "name", credentials_group_id),
                    )
            except Exception as e:
                logger.error(f"Error processing credentials group: {e}")
                continue

            if not credentials_group_id:
                continue

            response = self._list_access_keys_response(
                client, region, credentials_group_id
            )
            keys_list = self._extract_access_keys(response)

            for key_data in keys_list:
                try:
                    if hasattr(key_data, "key_id"):
                        key_id = key_data.key_id
                        display_name = getattr(key_data, "display_name", key_id)
                        expires = getattr(key_data, "expires", None)
                    elif isinstance(key_data, dict):
                        key_id = key_data.get("keyId", key_data.get("key_id", ""))
                        display_name = key_data.get(
                            "displayName", key_data.get("display_name", key_id)
                        )
                        expires = key_data.get("expires")
                    else:
                        continue

                    if not key_id:
                        continue

                    self.access_keys.append(
                        AccessKey(
                            key_id=key_id,
                            display_name=display_name,
                            expires=expires,
                            region=region,
                            project_id=self.project_id,
                            credentials_group_id=credentials_group_id,
                            credentials_group_name=credentials_group_name,
                        )
                    )
                except Exception as e:
                    logger.error(f"Error processing access key: {e}")
                    continue

            total_keys += len(keys_list)

        logger.info(f"Listed {total_keys} access keys in {region}")

    def _list_access_keys_response(
        self, client, region: str, credentials_group_id: str
    ):
        raw_method = None
        if callable(
            getattr(type(client), "list_access_keys_without_preload_content", None)
        ):
            raw_method = client.list_access_keys_without_preload_content
        elif callable(vars(client).get("list_access_keys_without_preload_content")):
            raw_method = vars(client)["list_access_keys_without_preload_content"]

        if raw_method:
            response = self._handle_api_call(
                raw_method,
                project_id=self.project_id,
                region=region,
                credentials_group=credentials_group_id,
            )
            self._raise_for_raw_response_status(response)
            return response

        return self._handle_api_call(
            client.list_access_keys,
            project_id=self.project_id,
            region=region,
            credentials_group=credentials_group_id,
        )

    def _raise_for_raw_response_status(self, response):
        status = getattr(response, "status", None)
        if status is None:
            status = getattr(response, "status_code", None)
        if isinstance(status, int) and status >= 400:
            error = Exception(
                f"StackIT ObjectStorage list_access_keys failed with status {status}"
            )
            error.status = status
            self.provider.handle_api_error(error)
            raise error

    @staticmethod
    def _extract_access_keys(response) -> list:
        payload = response
        if not isinstance(payload, (dict, list)):
            json_method = getattr(response, "json", None)
            if callable(json_method):
                payload = json_method()
            elif hasattr(response, "data"):
                payload = ObjectStorageService._parse_raw_json(response.data)
            elif hasattr(response, "text"):
                payload = ObjectStorageService._parse_raw_json(response.text)

        if isinstance(payload, dict):
            return payload.get("accessKeys", payload.get("access_keys", []))
        if isinstance(payload, list):
            return payload
        return getattr(response, "access_keys", None) or []

    @staticmethod
    def _parse_raw_json(raw):
        if raw in (None, b"", ""):
            return {}
        if isinstance(raw, (bytes, bytearray)):
            raw = raw.decode("utf-8")
        if isinstance(raw, str):
            return json.loads(raw)
        return raw


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
    credentials_group_id: Optional[str] = None
    credentials_group_name: Optional[str] = None

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
        expires_str = self.expires.replace("Z", "+00:00")
        dt = datetime.fromisoformat(expires_str)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        delta = dt - datetime.now(tz=timezone.utc)
        return delta.days <= days
