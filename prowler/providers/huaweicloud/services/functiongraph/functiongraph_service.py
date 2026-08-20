from typing import List, Optional

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.huaweicloud.lib.service.service import HuaweiCloudService
from prowler.providers.huaweicloud.models import HuaweiCloudBaseModel


class FunctionGraph(HuaweiCloudService):
    """
    FunctionGraph service class for Huawei Cloud.

    This class provides methods to interact with Huawei Cloud FunctionGraph service
    to retrieve serverless functions and their security configuration.
    """

    def __init__(self, provider):
        super().__init__(__class__.__name__, provider)

        self.functions: List[FunctionGraphFunction] = []

        if getattr(self.session, "is_mock", False):
            self._load_mock_data()
            return

        self.__threading_call__(self._list_functions)

    def _load_mock_data(self):
        """Load mock data for testing."""
        region = "la-south-2"
        self.functions = [
            FunctionGraphFunction(
                id="fg-mock-001",
                name="function-secure",
                arn="urn:fss:la-south-2:project:function:default:function-secure:latest",
                runtime="Python3.9",
                timeout=30,
                memory_size=128,
                vpc_id="vpc-12345",
                region=region,
            ),
            FunctionGraphFunction(
                id="fg-mock-002",
                name="function-insecure",
                arn="urn:fss:la-south-2:project:function:default:function-insecure:latest",
                runtime="Python3.9",
                timeout=30,
                memory_size=128,
                vpc_id=None,
                region=region,
            ),
        ]

    def _list_functions(self, regional_client):
        """List every FunctionGraph function in one region."""
        region = getattr(regional_client, "region", "unknown")
        logger.info(f"FunctionGraph - Listing Functions in {region}...")
        discovered_functions = []
        marker = None

        try:
            from huaweicloudsdkfunctiongraph.v2 import ListFunctionsRequest

            while True:
                request = ListFunctionsRequest(marker=marker, maxitems="400")
                response = self._call_with_retries(
                    regional_client.list_functions, request
                )

                for function in getattr(response, "functions", None) or []:
                    resource_id = getattr(function, "resource_id", None) or ""
                    if self.audit_resources and not is_resource_filtered(
                        resource_id, self.audit_resources
                    ):
                        continue
                    discovered_functions.append(
                        FunctionGraphFunction(
                            id=resource_id,
                            name=getattr(function, "func_name", None) or resource_id,
                            arn=getattr(function, "func_urn", None) or "",
                            runtime=getattr(function, "runtime", None) or "",
                            timeout=getattr(function, "timeout", None) or 0,
                            memory_size=getattr(function, "memory_size", None) or 0,
                            vpc_id=getattr(function, "func_vpc_id", None),
                            region=region,
                        )
                    )

                next_marker = getattr(response, "next_marker", None)
                if not next_marker or str(next_marker) == marker:
                    break
                marker = str(next_marker)

            self.functions.extend(discovered_functions)
        except Exception as error:
            logger.error(
                f"{region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class FunctionGraphFunction(HuaweiCloudBaseModel):
    """FunctionGraph function model."""

    id: str
    name: str = ""
    arn: str = ""
    runtime: str = ""
    timeout: int = 0
    memory_size: int = 0
    vpc_id: Optional[str] = None
    region: str = ""
