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


# Only mock if oci import fails (missing dependencies)
try:
    pass
except (ImportError, ModuleNotFoundError):
    # Create mock OCI module
    mock_oci = MockOCIModule()
    sys.modules["oci"] = mock_oci
    sys.modules["oci.auth"] = mock_oci.auth
    sys.modules["oci.config"] = mock_oci.config
    sys.modules["oci.identity"] = mock_oci.identity
    sys.modules["oci.core"] = mock_oci.core
    sys.modules["oci.object_storage"] = mock_oci.object_storage
    sys.modules["oci.key_management"] = mock_oci.key_management
    sys.modules["oci.file_storage"] = mock_oci.file_storage
    sys.modules["oci.block_storage"] = mock_oci.block_storage
    sys.modules["oci.database"] = mock_oci.database
    sys.modules["oci.events"] = mock_oci.events
    sys.modules["oci.cloud_guard"] = mock_oci.cloud_guard
    sys.modules["oci.audit"] = mock_oci.audit
    sys.modules["oci.analytics"] = mock_oci.analytics
    sys.modules["oci.integration"] = mock_oci.integration
    sys.modules["oci.logging"] = mock_oci.logging
    sys.modules["oci.pagination"] = mock_oci.pagination
    sys.modules["oci.exceptions"] = mock_oci.exceptions
