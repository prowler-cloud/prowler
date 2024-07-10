from mock import MagicMock

from prowler.lib.outputs.compliance.compliance import (
    get_check_compliance_frameworks_in_input,
)
from tests.lib.outputs.compliance.fixtures import (
    CIS_1_4_AWS,
    CIS_1_4_AWS_NAME,
    CIS_1_5_AWS,
    CIS_1_5_AWS_NAME,
    NOT_PRESENT_COMPLIANCE,
)


class TestCompliance:
    def test_get_check_compliance_frameworks_all_none(self):
        check_id = None
        bulk_checks_metadata = None
        input_compliance_frameworks = None
        assert (
            get_check_compliance_frameworks_in_input(
                check_id, bulk_checks_metadata, input_compliance_frameworks
            )
            == []
        )

    def test_get_check_compliance_frameworks_all(self):
        check_id = "test-check"
        bulk_check_metadata = [CIS_1_4_AWS, CIS_1_5_AWS]
        bulk_checks_metadata = {}
        bulk_checks_metadata[check_id] = MagicMock()
        bulk_checks_metadata[check_id].Compliance = bulk_check_metadata
        input_compliance_frameworks = [CIS_1_4_AWS_NAME, CIS_1_5_AWS_NAME]
        assert get_check_compliance_frameworks_in_input(
            check_id, bulk_checks_metadata, input_compliance_frameworks
        ) == [CIS_1_4_AWS, CIS_1_5_AWS]

    def test_get_check_compliance_frameworks_two_of_three(self):
        check_id = "test-check"
        bulk_check_metadata = [CIS_1_4_AWS, CIS_1_5_AWS, NOT_PRESENT_COMPLIANCE]
        bulk_checks_metadata = {}
        bulk_checks_metadata[check_id] = MagicMock()
        bulk_checks_metadata[check_id].Compliance = bulk_check_metadata
        input_compliance_frameworks = [CIS_1_4_AWS_NAME, CIS_1_5_AWS_NAME]
        assert get_check_compliance_frameworks_in_input(
            check_id, bulk_checks_metadata, input_compliance_frameworks
        ) == [CIS_1_4_AWS, CIS_1_5_AWS]
