from typing import List

from pydantic.v1 import BaseModel, Field

from prowler.providers.huaweicloud.lib.service.service import HuaweiCloudService


class IdentityCenterInstance(BaseModel):
    """Represent a Huawei Cloud Identity Center instance."""

    instance_id: str
    instance_urn: str = ""
    permission_sets: List[str] = Field(default_factory=list)


class IdentityCenter(HuaweiCloudService):
    """Discover Huawei Cloud Identity Center instances and permission sets."""

    def __init__(self, provider):
        super().__init__(__class__.__name__, provider, global_service=True)

        self.instances: List[IdentityCenterInstance] = []
        self.error: str | None = None

        if getattr(self.session, "is_mock", False):
            self._load_mock_data()
            return

        try:
            self._list_instances()
        except Exception as error:
            self.error = str(error)

    def _list_instances(self) -> None:
        """List every Identity Center instance and its permission sets."""
        from huaweicloudsdkidentitycenter.v1 import (
            ListInstancesRequest,
            ListPermissionSetsRequest,
        )

        instances = []
        marker = None
        while True:
            response = self._call_with_retries(
                self.client.list_instances,
                ListInstancesRequest(marker=marker),
            )
            if response and response.instances:
                instances.extend(response.instances)
            marker = getattr(getattr(response, "page_info", None), "next_marker", None)
            if not marker:
                break

        for instance in instances:
            permission_sets = []
            marker = None
            while True:
                response = self._call_with_retries(
                    self.client.list_permission_sets,
                    ListPermissionSetsRequest(
                        instance_id=instance.instance_id,
                        marker=marker,
                    ),
                )
                if response and response.permission_sets:
                    permission_sets.extend(
                        permission_set.permission_set_id
                        for permission_set in response.permission_sets
                    )
                marker = getattr(
                    getattr(response, "page_info", None), "next_marker", None
                )
                if not marker:
                    break

            self.instances.append(
                IdentityCenterInstance(
                    instance_id=instance.instance_id,
                    instance_urn=getattr(instance, "instance_urn", "") or "",
                    permission_sets=permission_sets,
                )
            )

    def _load_mock_data(self) -> None:
        """Load deterministic Identity Center data for mock scans."""
        self.instances = [
            IdentityCenterInstance(
                instance_id="idc-mock-001",
                instance_urn="IdentityCenter::system:instance:idc-mock-001",
                permission_sets=["ps-001", "ps-002"],
            )
        ]
