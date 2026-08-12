from typing import List

from pydantic.v1 import BaseModel

from prowler.providers.huaweicloud.lib.service.service import HuaweiCloudService
from prowler.providers.huaweicloud.models import HuaweiCloudSession


class IdentityCenterInstance(BaseModel):
    instance_id: str
    permission_sets: List[str] = []


class IdentityCenter(HuaweiCloudService):
    def __init__(self, provider):
        super().__init__(__class__.__name__, provider, global_service=True)

        self.instances: List[IdentityCenterInstance] = []

        if self.session.is_mock:
            self._load_mock_data()
            return

        try:
            self._list_instances()
        except Exception as error:
            self.session.error = str(error)

    def _list_instances(self):
        from huaweicloudsdkidentitycenter.v1 import (
            ListInstancesRequest,
            ListPermissionSetsRequest,
        )

        client = self.session.client("identitycenter", self.region)

        response = self._call_with_retries(
            client.list_instances,
            ListInstancesRequest(),
        )

        if response and response.instances:
            for instance in response.instances:
                permission_sets = []
                ps_response = self._call_with_retries(
                    client.list_permission_sets,
                    ListPermissionSetsRequest(instance_id=instance.instance_id),
                )
                if ps_response and ps_response.permission_sets:
                    permission_sets = list(ps_response.permission_sets)

                self.instances.append(
                    IdentityCenterInstance(
                        instance_id=instance.instance_id,
                        permission_sets=permission_sets,
                    )
                )

    def _load_mock_data(self):
        self.instances = [
            IdentityCenterInstance(
                instance_id="idc-mock-001",
                permission_sets=["ps-001", "ps-002"],
            )
        ]
