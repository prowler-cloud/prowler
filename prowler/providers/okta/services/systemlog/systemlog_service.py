from typing import Optional

from pydantic import BaseModel, ValidationError

from prowler.lib.logger import logger
from prowler.providers.okta.lib.service.pagination import paginate
from prowler.providers.okta.lib.service.raw_fetch import (
    get_json_paginated as raw_get_json_paginated,
)
from prowler.providers.okta.lib.service.service import OktaService

REQUIRED_SCOPES: dict[str, str] = {
    "log_streams": "okta.logStreams.read",
}


class SystemLog(OktaService):
    """Fetches Okta Log Stream configurations.

    Populates `self.log_streams` keyed by Log Stream id. Each entry
    carries `name`, `status`, `type` — enough for the streaming-enabled
    check to evaluate whether the tenant has off-loaded audit records
    to an external SIEM/event bus.

    Required OAuth scopes (`REQUIRED_SCOPES`) are compared against the
    access token's granted scopes (`provider.identity.granted_scopes`).
    Missing scopes are recorded in `self.missing_scope` so the check
    can emit an explicit MANUAL finding instead of a misleading
    "no resources returned".
    """

    def __init__(self, provider):
        super().__init__(__class__.__name__, provider)
        granted = set(getattr(provider.identity, "granted_scopes", None) or [])
        self.missing_scope: dict[str, Optional[str]] = {
            resource: (scope if granted and scope not in granted else None)
            for resource, scope in REQUIRED_SCOPES.items()
        }

        self.log_streams: dict[str, LogStream] = (
            {} if self.missing_scope["log_streams"] else self._list_log_streams()
        )

    def _list_log_streams(self) -> dict:
        logger.info("SystemLog - Listing Okta Log Streams...")
        try:
            return self._run(self._fetch_log_streams())
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            return {}

    async def _fetch_log_streams(self) -> dict:
        result: dict[str, LogStream] = {}
        try:
            all_streams, err = await paginate(
                lambda after: self.client.list_log_streams(after=after)
            )
        except ValidationError as ve:
            # Upstream okta-sdk-python bug: e.g. `LogStreamSettingsAws`'s
            # `eventSourceName` validator regex is `^[a-zA-Z0-9.\-_]$` —
            # missing the `+` quantifier, so it rejects every
            # multi-character name. Fall back to raw JSON so the check
            # can still evaluate the tenant's actual log-stream state.
            # Remove this workaround once okta-sdk-python fixes the
            # validator (issue to be filed upstream).
            logger.warning(
                f"Okta SDK raised ValidationError parsing log streams "
                f"({ve.error_count()} error(s)) — falling back to raw-JSON "
                "parse. This is an okta-sdk-python deserialization bug."
            )
            return await self._fetch_log_streams_raw()

        if err is not None:
            logger.error(f"Error listing log streams: {err}")
            return result

        for stream in all_streams:
            stream_id = getattr(stream, "id", "") or ""
            if not stream_id:
                continue
            result[stream_id] = LogStream(
                id=stream_id,
                name=getattr(stream, "name", "") or "",
                status=getattr(stream, "status", "") or "",
                type=_stringify_enum(getattr(stream, "type", None)) or "",
            )
        return result

    async def _fetch_log_streams_raw(self) -> dict:
        """Raw-JSON fallback for `list_log_streams`.

        Bypasses the SDK's typed deserialization via the shared
        `get_json_paginated` helper (which follows the `Link: rel=next`
        cursor so tenants with >200 streams are not silently truncated),
        and projects the response onto our own pydantic snapshot which
        only validates the four fields the check reads. Keeps the check
        evaluable on tenants whose Log Stream settings happen to trip
        an SDK enum/regex validator.
        """
        result: dict[str, LogStream] = {}
        data = await raw_get_json_paginated(
            self.client,
            "/api/v1/logStreams",
            page_size=200,
            context="log streams",
        )
        if data is None:
            return result
        for item in data:
            if not isinstance(item, dict):
                continue
            stream_id = item.get("id")
            if not stream_id:
                continue
            result[stream_id] = LogStream(
                id=stream_id,
                name=item.get("name") or "",
                status=(item.get("status") or "").upper(),
                type=item.get("type") or "",
            )
        return result


def _stringify_enum(value) -> Optional[str]:
    if value is None:
        return None
    return getattr(value, "value", None) or str(value)


class LogStream(BaseModel):
    id: str
    name: str = ""
    status: str = ""
    type: str = ""
