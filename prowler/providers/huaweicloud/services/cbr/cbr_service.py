from typing import List

from pydantic.v1 import BaseModel

from prowler.lib.logger import logger
from prowler.providers.huaweicloud.lib.service.service import HuaweiCloudService


class CBR(HuaweiCloudService):
    """
    CBR (Cloud Backup and Recovery) service class for Huawei Cloud.

    This class provides methods to interact with Huawei Cloud CBR service
    to retrieve vaults and backup policies.
    """

    def __init__(self, provider):
        super().__init__(__class__.__name__, provider)

        self.vaults: List[CBRVault] = []
        self.policies: List[CBRPolicy] = []

        if self.session.is_mock:
            self._load_mock_data()
            return

        self._list_vaults()
        self._list_policies()

    def _load_mock_data(self):
        """Load mock data for testing."""
        region = "la-south-2"
        self.vaults = [
            CBRVault(
                vault_id="cbr-vault-001",
                name="vault-with-resources",
                resources=["resource-1", "resource-2"],
                region=region,
            ),
            CBRVault(
                vault_id="cbr-vault-002",
                name="vault-empty",
                resources=[],
                region=region,
            ),
        ]
        self.policies = [
            CBRPolicy(
                policy_id="cbr-policy-001",
                name="policy-good-retention",
                retention_duration_days=30,
                region=region,
            ),
            CBRPolicy(
                policy_id="cbr-policy-002",
                name="policy-short-retention",
                retention_duration_days=3,
                region=region,
            ),
        ]

    def _list_vaults(self):
        """List all CBR vaults across regions."""
        if not self.regional_clients:
            return

        for region, client in self.regional_clients.items():
            logger.info(f"CBR - Listing Vaults in {region}...")

            try:
                from huaweicloudsdkcbr.v1 import ListVaultRequest

                request = ListVaultRequest()
                response = self._call_with_retries(client.list_vault, request)

                if response and response.vaults:
                    for vault in response.vaults:
                        vault_id = getattr(vault, "id", "")
                        name = getattr(vault, "name", "")
                        resources = getattr(vault, "resources", []) or []

                        self.vaults.append(
                            CBRVault(
                                vault_id=vault_id,
                                name=name,
                                resources=resources,
                                region=region,
                            )
                        )

            except Exception as error:
                logger.error(
                    f"{region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )

    def _list_policies(self):
        """List all CBR backup policies across regions."""
        if not self.regional_clients:
            return

        for region, client in self.regional_clients.items():
            logger.info(f"CBR - Listing Policies in {region}...")

            try:
                from huaweicloudsdkcbr.v1 import ListPoliciesRequest

                request = ListPoliciesRequest()
                response = self._call_with_retries(client.list_policies, request)

                if response and response.policies:
                    for policy in response.policies:
                        policy_id = getattr(policy, "id", "")
                        name = getattr(policy, "name", "")
                        retention_duration_days = 0
                        op_def = getattr(policy, "operation_definition", None)
                        if op_def:
                            retention_duration_days = (
                                getattr(op_def, "retention_duration_days", 0) or 0
                            )

                        self.policies.append(
                            CBRPolicy(
                                policy_id=policy_id,
                                name=name,
                                retention_duration_days=retention_duration_days,
                                region=region,
                            )
                        )

            except Exception as error:
                logger.error(
                    f"{region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )


class CBRVault(BaseModel):
    """CBR vault model."""

    vault_id: str
    name: str = ""
    resources: list = []
    region: str = ""


class CBRPolicy(BaseModel):
    """CBR backup policy model."""

    policy_id: str
    name: str = ""
    retention_duration_days: int = 0
    region: str = ""
