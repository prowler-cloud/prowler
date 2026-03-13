"""
Pytest configuration for OCI provider tests.

This file sets up mocking for OCI SDK imports to avoid dependency issues
when running tests without full OCI SDK installation.
"""

import sys
from unittest.mock import MagicMock


# Mock the OCI module and its submodules to avoid import errors
# when cffi_backend is not available
class MockOCIModule(MagicMock):
    """Mock OCI module to avoid import errors"""

    def __getattr__(self, name):
        return MagicMock()


# Only mock if oraclecloud import fails (missing dependencies)
try:
    pass
except (ImportError, ModuleNotFoundError):
    # Create mock OCI module
    mock_oci = MockOCIModule()
    sys.modules["oraclecloud"] = mock_oci
    sys.modules["oraclecloud.auth"] = mock_oci.auth
    sys.modules["oraclecloud.config"] = mock_oci.config
    sys.modules["oraclecloud.identity"] = mock_oci.identity
    sys.modules["oraclecloud.core"] = mock_oci.core
    sys.modules["oraclecloud.object_storage"] = mock_oci.object_storage
    sys.modules["oraclecloud.key_management"] = mock_oci.key_management
    sys.modules["oraclecloud.file_storage"] = mock_oci.file_storage
    sys.modules["oraclecloud.block_storage"] = mock_oci.block_storage
    sys.modules["oraclecloud.database"] = mock_oci.database
    sys.modules["oraclecloud.events"] = mock_oci.events
    sys.modules["oraclecloud.cloud_guard"] = mock_oci.cloud_guard
    sys.modules["oraclecloud.audit"] = mock_oci.audit
    sys.modules["oraclecloud.analytics"] = mock_oci.analytics
    sys.modules["oraclecloud.integration"] = mock_oci.integration
    sys.modules["oraclecloud.logging"] = mock_oci.logging
    sys.modules["oraclecloud.pagination"] = mock_oci.pagination
    sys.modules["oraclecloud.exceptions"] = mock_oci.exceptions
