from datetime import datetime
from unittest.mock import MagicMock

from prowler.providers.common.models import Audit_Metadata
from prowler.providers.oraclecloud.models import (
    OCICompartment,
    OCIIdentityInfo,
    OCIRegionalClient,
    OCISession,
)

OCI_TENANCY_ID = "ocid1.tenancy.oc1..aaaaaaaexample"
OCI_TENANCY_NAME = "test-tenancy"
OCI_COMPARTMENT_ID = "ocid1.compartment.oc1..aaaaaaaexample"
OCI_USER_ID = "ocid1.user.oc1..aaaaaaaexample"
OCI_REGION = "us-ashburn-1"


def set_mocked_oraclecloud_provider(
    tenancy_id: str = OCI_TENANCY_ID,
    tenancy_name: str = OCI_TENANCY_NAME,
    user_id: str = OCI_USER_ID,
    region: str = OCI_REGION,
) -> MagicMock:
    """Create a mocked OCI provider for testing"""
    provider = MagicMock()
    provider.type = "oraclecloud"

    # Mock session
    provider.session = OCISession(
        config={
            "tenancy": tenancy_id,
            "user": user_id,
            "region": region,
            "fingerprint": "aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99",
        },
        signer=MagicMock(),
        profile="DEFAULT",
    )

    # Mock identity
    provider.identity = OCIIdentityInfo(
        tenancy_id=tenancy_id,
        tenancy_name=tenancy_name,
        user_id=user_id,
        region=region,
        profile="DEFAULT",
        audited_regions={region},
        audited_compartments=[OCI_COMPARTMENT_ID],
    )

    # Mock compartments
    provider.compartments = {
        tenancy_id: OCICompartment(
            id=tenancy_id,
            name="root",
            lifecycle_state="ACTIVE",
            time_created=datetime.now(),
        ),
        OCI_COMPARTMENT_ID: OCICompartment(
            id=OCI_COMPARTMENT_ID,
            name="test-compartment",
            lifecycle_state="ACTIVE",
            time_created=datetime.now(),
        ),
    }

    # Mock regions
    provider.regions = [region]

    # Mock audit metadata
    provider.audit_metadata = Audit_Metadata(
        services_scanned=0,
        expected_checks=[],
        completed_checks=0,
        audit_progress=0,
    )

    # Mock config
    provider.audit_config = {}
    provider.fixer_config = {}

    # Mock mutelist
    provider.mutelist = MagicMock()
    provider.mutelist.is_muted = MagicMock(return_value=False)

    # Mock generate_regional_clients method
    def mock_generate_regional_clients(service_name):
        return {
            region: OCIRegionalClient(
                client=MagicMock(),
                region=region,
            )
        }

    provider.generate_regional_clients = mock_generate_regional_clients

    return provider
