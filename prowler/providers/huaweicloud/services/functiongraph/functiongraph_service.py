from typing import List, Optional

from pydantic.v1 import BaseModel

from prowler.lib.logger import logger
from prowler.providers.huaweicloud.lib.service.service import HuaweiCloudService


class FunctionGraph(HuaweiCloudService):
    """
    FunctionGraph service class for Huawei Cloud.

    This class provides methods to interact with Huawei Cloud FunctionGraph service
    to retrieve serverless functions and their security configuration.
    """

    def __init__(self, provider):
        super().__init__(__class__.__name__, provider)

        self.functions: List[FunctionGraphFunction] = []

        if self.session.is_mock:
            self._load_mock_data()
            return

        self._list_functions()

    def _load_mock_data(self):
        """Load mock data for testing."""
        region = "la-south-2"
        self.functions = [
            FunctionGraphFunction(
                function_id="fg-mock-001",
                name="function-secure",
                runtime="Python3.9",
                timeout=30,
                memory_size=128,
                func_vpc_id="vpc-12345",
                region=region,
            ),
            FunctionGraphFunction(
                function_id="fg-mock-002",
                name="function-insecure",
                runtime="Python3.9",
                timeout=30,
                memory_size=128,
                func_vpc_id=None,
                region=region,
            ),
        ]

    def _list_functions(self):
        """List all FunctionGraph functions across regions."""
        if not self.regional_clients:
            return

        for region, client in self.regional_clients.items():
            logger.info(f"FunctionGraph - Listing Functions in {region}...")

            try:
                from huaweicloudsdkfunctiongraph.v2 import ListFunctionsRequest

                request = ListFunctionsRequest()
                response = self._call_with_retries(client.list_functions, request)

                if response and response.functions:
                    for func in response.functions:
                        self.functions.append(
                            FunctionGraphFunction(
                                function_id=getattr(func, "resource_id", ""),
                                name=getattr(func, "func_name", ""),
                                runtime=getattr(func, "runtime", ""),
                                timeout=getattr(func, "timeout", 0),
                                memory_size=getattr(func, "memory_size", 0),
                                func_vpc_id=getattr(func, "func_vpc_id", None),
                                region=region,
                            )
                        )

            except Exception as error:
                logger.error(
                    f"{region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )


class FunctionGraphFunction(BaseModel):
    """FunctionGraph function model."""

    function_id: str
    name: str = ""
    runtime: str = ""
    timeout: int = 0
    memory_size: int = 0
    func_vpc_id: Optional[str] = None
    region: str = ""
