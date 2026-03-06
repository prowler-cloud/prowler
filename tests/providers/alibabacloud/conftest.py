"""
Pytest configuration for Alibaba Cloud provider tests.

Mocks Alibaba Cloud SDK modules to avoid import issues when the real
dependencies are not installed in the test environment.
"""

import sys
from unittest.mock import MagicMock

# Mock Alibaba Cloud SDK modules so imports in provider/service code succeed
MOCKED_MODULES = [
    "alibabacloud_credentials",
    "alibabacloud_credentials.client",
    "alibabacloud_credentials.models",
    "alibabacloud_sts20150401",
    "alibabacloud_sts20150401.client",
    "alibabacloud_tea_openapi",
    "alibabacloud_tea_openapi.models",
    "alibabacloud_ram20150501",
    "alibabacloud_ram20150501.client",
    "alibabacloud_vpc20160428",
    "alibabacloud_vpc20160428.client",
    "alibabacloud_sas20181203",
    "alibabacloud_sas20181203.client",
    "alibabacloud_ecs20140526",
    "alibabacloud_ecs20140526.client",
    "alibabacloud_oss20190517",
    "alibabacloud_oss20190517.client",
    "alibabacloud_actiontrail20200706",
    "alibabacloud_actiontrail20200706.client",
    "alibabacloud_cs20151215",
    "alibabacloud_cs20151215.client",
    "alibabacloud_rds20140815",
    "alibabacloud_rds20140815.client",
    "alibabacloud_sls20201230",
    "alibabacloud_sls20201230.client",
]

for module_name in MOCKED_MODULES:
    sys.modules.setdefault(module_name, MagicMock())
