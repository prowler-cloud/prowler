from typing import Optional

from pydantic.v1 import BaseModel

from prowler.lib.logger import logger
from prowler.providers.stackit.stackit_provider import StackitProvider, suppress_stderr

# Source ranges that place no restriction on who may reach the Kubernetes API.
UNRESTRICTED_CIDRS = frozenset({"0.0.0.0/0", "::/0"})

# Control plane access scope that keeps the Kubernetes API inside a STACKIT
# Network Area instead of publishing it on the internet.
PRIVATE_ACCESS_SCOPE = "SNA"


class SKEService:
    """
    StackIT Kubernetes Engine (SKE) service class to handle cluster operations.

    This service uses the StackIT Python SDK to access SKE resources.
    Authentication is delegated to the SDK, which signs the RSA challenge
    in the configured service account key and refreshes access tokens
    internally for the life of the scan.
    """

    def __init__(self, provider: StackitProvider):
        """
        Initialize the SKE service.

        Args:
            provider: The StackIT provider instance
        """
        self.provider = provider
        self.project_id = provider.identity.project_id
        self.service_account_key_path = provider.session.get("service_account_key_path")

        # Generate regional clients (AWS pattern)
        self.regional_clients = provider.generate_regional_clients("ske")
        self.audited_regions = provider.identity.audited_regions

        # Initialize cluster list
        self.clusters: list[Cluster] = []

        # Fetch resources from all regions
        self._fetch_all_regions()

    def _fetch_all_regions(self):
        """Fetch SKE clusters from all audited regions.

        A project is not necessarily provisioned in every StackIT region. A
        region where the project does not exist answers the SKE endpoints with
        HTTP 404 (``resource not found: project``). That is expected, so the
        region is skipped and the scan continues with the remaining regions
        instead of aborting.

        Credential and permission failures (401/403) still propagate via
        ``handle_api_error`` so a misconfigured account fails loudly.
        """
        for region, client in self.regional_clients.items():
            try:
                self._list_clusters(client, region)
            except Exception as error:
                if getattr(error, "status", None) == 404:
                    logger.info(
                        f"StackIT project {self.project_id} has no SKE presence "
                        f"in region {region} (404 resource not found); skipping "
                        f"this region."
                    )
                    continue
                raise

    @staticmethod
    def _extract_items(response, endpoint_name: str) -> list:
        """Extract the items list from a StackIT SDK response.

        Handles three response shapes safely:
            - SDK model exposing an ``items`` attribute (not the ``dict.items`` method)
            - Raw ``dict`` with an ``"items"`` key
            - Plain ``list``

        ``isinstance(response, dict)`` is checked first because ``dict`` has an
        ``items`` *method*; ``hasattr(response, "items")`` is otherwise True for
        plain dicts and silently returns the bound method.
        """
        if isinstance(response, dict):
            return response.get("items", [])
        if isinstance(response, list):
            return response
        items_attr = getattr(response, "items", None)
        if items_attr is not None and not callable(items_attr):
            return items_attr
        logger.warning(
            f"Unexpected response type from {endpoint_name}: {type(response)}"
        )
        return []

    @staticmethod
    def _get_field(item, *keys, default=None):
        """Read a field from an SDK model (attribute) or a raw ``dict`` (key).

        ``_extract_items`` yields either SDK models or raw dicts, so the nested
        cluster parsing must read fields from both shapes. Multiple key aliases
        are accepted so snake_case SDK attributes and camelCase API/dict keys
        are both supported (e.g. ``allowed_cidrs`` / ``allowedCidrs``). ``None``
        items return ``default`` so nested lookups can be chained safely.
        Returns the first non-None match, otherwise ``default``.
        """
        if item is None:
            return default
        if isinstance(item, dict):
            for key in keys:
                value = item.get(key)
                if value is not None:
                    return value
            return default
        for key in keys:
            value = getattr(item, key, None)
            if value is not None:
                return value
        return default

    def _handle_api_call(self, api_function, *args, **kwargs):
        """
        Centralized API call handler with authentication error detection.

        Args:
            api_function: The API function to call
            *args: Positional arguments to pass to the API function
            **kwargs: Keyword arguments to pass to the API function

        Returns:
            The API response

        Raises:
            StackITInvalidTokenError: If authentication fails (401)
        """
        try:
            # Suppress StackIT SDK stderr messages during API calls
            with suppress_stderr():
                return api_function(*args, **kwargs)
        except Exception as e:
            # Use centralized error handler from provider
            self.provider.handle_api_error(e)
            raise

    @classmethod
    def _parse_access_scope(cls, cluster_data) -> Optional[str]:
        """Return the control plane access scope of a cluster, if declared.

        The scope lives at ``network.controlPlane.accessScope``. Every level of
        that chain is optional because the private (``SNA``) control plane is an
        opt-in preview feature, so most clusters omit it entirely. ``None`` is
        returned in that case and the caller falls back to the ACL extension.
        """
        network = cls._get_field(cluster_data, "network")
        control_plane = cls._get_field(network, "control_plane", "controlPlane")
        access_scope = cls._get_field(control_plane, "access_scope", "accessScope")
        if access_scope is None:
            return None
        # ``AccessScope`` is a ``str`` Enum, whose ``str()`` renders as
        # "AccessScope.SNA" rather than the "SNA" wire value.
        return str(getattr(access_scope, "value", access_scope))

    @classmethod
    def _parse_acl(cls, cluster_data) -> tuple[bool, list[str]]:
        """Return the ``(enabled, allowed_cidrs)`` pair of the cluster ACL extension.

        The ACL extension restricts which source CIDRs may reach the Kubernetes
        API and lives at ``extensions.acl``. When the extension is absent the
        API server accepts connections from any address, which is reported here
        as ``(False, [])``.
        """
        extensions = cls._get_field(cluster_data, "extensions")
        acl = cls._get_field(extensions, "acl")
        enabled = bool(cls._get_field(acl, "enabled", default=False))
        allowed_cidrs = (
            cls._get_field(acl, "allowed_cidrs", "allowedCidrs", default=[]) or []
        )
        return enabled, [str(cidr) for cidr in allowed_cidrs]

    def _list_clusters(self, client, region: str):
        """
        List all SKE clusters in the StackIT project for a single region.

        Populates ``self.clusters`` with :class:`Cluster` objects describing the
        control plane access scope and the ACL extension of each cluster.
        """
        if not client:
            logger.warning(
                f"Cannot list SKE clusters in {region}: StackIT SKE client not available"
            )
            return

        response = self._handle_api_call(
            client.list_clusters, project_id=self.project_id, region=region
        )

        clusters_list = self._extract_items(response, "list_clusters")

        for cluster_data in clusters_list:
            try:
                cluster_name = str(self._get_field(cluster_data, "name") or "")
                acl_enabled, allowed_cidrs = self._parse_acl(cluster_data)
                cluster = Cluster(
                    # SKE addresses a cluster by its name; the API exposes no
                    # separate identifier, so the name doubles as the id.
                    id=cluster_name,
                    name=cluster_name,
                    project_id=self.project_id,
                    region=region,
                    access_scope=self._parse_access_scope(cluster_data),
                    acl_enabled=acl_enabled,
                    allowed_cidrs=allowed_cidrs,
                )
                self.clusters.append(cluster)
            except Exception as e:
                logger.error(f"Error processing SKE cluster: {e}")
                continue

        logger.info(
            f"Successfully listed {len(clusters_list)} SKE clusters in {region}"
        )


class Cluster(BaseModel):
    """
    Represents a StackIT SKE Cluster.

    Attributes:
        id: The unique identifier of the cluster (SKE uses the cluster name)
        name: The name of the cluster
        project_id: The StackIT project ID containing the cluster
        region: The region where the cluster runs
        access_scope: Control plane access scope ("PUBLIC"/"SNA"), None when unset
        acl_enabled: Whether the ACL extension restricting API access is enabled
        allowed_cidrs: Source CIDRs allowed to reach the Kubernetes API
    """

    id: str
    name: str
    project_id: str
    region: str
    access_scope: Optional[str] = None
    acl_enabled: bool = False
    allowed_cidrs: list[str] = []

    def has_private_control_plane(self) -> bool:
        """Check whether the control plane is confined to a STACKIT Network Area."""
        return self.access_scope == PRIVATE_ACCESS_SCOPE

    def unrestricted_cidrs(self) -> list[str]:
        """Return the allowed CIDRs that permit access from any source address."""
        return [cidr for cidr in self.allowed_cidrs if cidr in UNRESTRICTED_CIDRS]

    def has_public_endpoint(self) -> bool:
        """Check whether the Kubernetes API endpoint is reachable from the internet.

        A cluster is publicly reachable when its control plane is not confined to
        a STACKIT Network Area and either the ACL extension is disabled (no source
        restriction at all) or the allowlist itself contains an unrestricted range.
        """
        if self.has_private_control_plane():
            return False
        if not self.acl_enabled:
            return True
        return bool(self.unrestricted_cidrs())
