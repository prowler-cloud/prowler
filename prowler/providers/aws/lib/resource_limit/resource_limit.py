from threading import Lock

from prowler.lib.logger import logger

RESOURCE_SCAN_LIMITS_CONFIG_KEY = "resource_scan_limits"


class ResourceScanLimiter:
    def __init__(self, audit_config: dict, service: str, bypass_limits: bool = False):
        self._config = audit_config.get(RESOURCE_SCAN_LIMITS_CONFIG_KEY, {}) or {}
        self._service = service
        self._bypass_limits = bypass_limits
        self._counters = {}
        self._lock = Lock()
        if not self._bypass_limits and self.has_active_limits():
            logger.warning(
                "AWS resource scan limits are active for service "
                f"{service}. Explicit --resource-arn scans bypass these limits. "
                "Resource discovery may be truncated and compliance results may be incomplete."
            )

    def has_active_limits(self) -> bool:
        service_config = self._service_config()
        resource_types = service_config.get("resource_types", {}) or {}
        if any(
            self._parse_limit(limit) is not None
            for limit in resource_types.values()
            if limit is not None
        ):
            return True
        if service_config.get("default") is not None:
            return self._parse_limit(service_config.get("default")) is not None
        if "default" in self._config:
            return self._parse_limit(self._config.get("default")) is not None
        return False

    def limit_for(self, resource_type: str) -> int | None:
        if self._bypass_limits:
            return None

        service_config = self._service_config()
        resource_types = service_config.get("resource_types", {}) or {}
        if resource_types.get(resource_type) is not None:
            return self._parse_limit(resource_types.get(resource_type))
        if service_config.get("default") is not None:
            return self._parse_limit(service_config.get("default"))
        if "default" in self._config:
            return self._parse_limit(self._config.get("default"))
        return None

    def allow(self, resource_type: str) -> bool:
        limit = self.limit_for(resource_type)
        if limit is None:
            return True

        with self._lock:
            count = self._counters.get(resource_type, 0)
            if count >= limit:
                return False
            self._counters[resource_type] = count + 1
            return True

    def _service_config(self) -> dict:
        services = self._config.get("services", {}) or {}
        return services.get(self._service, {}) or {}

    def _parse_limit(self, raw_limit) -> int | None:
        if isinstance(raw_limit, bool):
            logger.warning(
                "Invalid AWS resource scan limit value "
                f"{raw_limit!r} for service {self._service}; treating it as unlimited."
            )
            return None
        if raw_limit is None or raw_limit == 0:
            return None
        if isinstance(raw_limit, int) and raw_limit > 0:
            return raw_limit
        logger.warning(
            "Invalid AWS resource scan limit value "
            f"{raw_limit!r} for service {self._service}; treating it as unlimited."
        )
        return None
