from unittest import mock

from tests.providers.m365.m365_fixtures import DOMAIN, set_mocked_m365_provider


class Test_defender_identity_health_issues_no_open:
    def test_no_health_issues(self):
        """Test when there are no health issues (empty list): expected PASS."""
        defender_identity_client = mock.MagicMock()
        defender_identity_client.audited_tenant = "audited_tenant"
        defender_identity_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.defender.defender_identity_health_issues_no_open.defender_identity_health_issues_no_open.defender_identity_client",
                new=defender_identity_client,
            ),
        ):
            from prowler.providers.m365.services.defender.defender_identity_health_issues_no_open.defender_identity_health_issues_no_open import (
                defender_identity_health_issues_no_open,
            )

            defender_identity_client.health_issues = []

            check = defender_identity_health_issues_no_open()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "No health issues found in Defender for Identity."
            )
            assert result[0].resource == {}
            assert result[0].resource_name == "Defender for Identity"
            assert result[0].resource_id == "defenderIdentity"

    def test_health_issues_none(self):
        """Test when health_issues is None (API failed): expected FAIL."""
        defender_identity_client = mock.MagicMock()
        defender_identity_client.audited_tenant = "audited_tenant"
        defender_identity_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.defender.defender_identity_health_issues_no_open.defender_identity_health_issues_no_open.defender_identity_client",
                new=defender_identity_client,
            ),
        ):
            from prowler.providers.m365.services.defender.defender_identity_health_issues_no_open.defender_identity_health_issues_no_open import (
                defender_identity_health_issues_no_open,
            )

            defender_identity_client.health_issues = None

            check = defender_identity_health_issues_no_open()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Defender for Identity data is unavailable. Ensure the tenant is onboarded to Microsoft Defender for Identity and the required permissions are granted."
            )
            assert result[0].resource == {}
            assert result[0].resource_name == "Defender for Identity"
            assert result[0].resource_id == "defenderIdentity"

    def test_health_issue_resolved(self):
        """Test when a health issue has been resolved (status is not open)."""
        defender_identity_client = mock.MagicMock()
        defender_identity_client.audited_tenant = "audited_tenant"
        defender_identity_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.defender.defender_identity_health_issues_no_open.defender_identity_health_issues_no_open.defender_identity_client",
                new=defender_identity_client,
            ),
        ):
            from prowler.providers.m365.services.defender.defender_identity_health_issues_no_open.defender_identity_health_issues_no_open import (
                defender_identity_health_issues_no_open,
            )
            from prowler.providers.m365.services.defender.defender_service import (
                HealthIssue,
            )

            health_issue_id = "test-health-issue-id-1"
            health_issue_name = "Test Health Issue Resolved"

            defender_identity_client.health_issues = [
                HealthIssue(
                    id=health_issue_id,
                    display_name=health_issue_name,
                    description="A test health issue that has been resolved",
                    health_issue_type="sensor",
                    severity="medium",
                    status="closed",
                    created_date_time="2024-01-01T00:00:00Z",
                    last_modified_date_time="2024-01-02T00:00:00Z",
                    domain_names=["example.com"],
                    sensor_dns_names=["sensor1.example.com"],
                    issue_type_id="test-issue-type-1",
                    recommendations=["Fix the issue"],
                    additional_information=[],
                )
            ]

            check = defender_identity_health_issues_no_open()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Defender for Identity sensor health issue '{health_issue_name}' is resolved."
            )
            assert result[0].resource_id == health_issue_id
            assert result[0].resource_name == health_issue_name

    def test_health_issue_open_high_severity(self):
        """Test when a health issue is open with high severity."""
        defender_identity_client = mock.MagicMock()
        defender_identity_client.audited_tenant = "audited_tenant"
        defender_identity_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.defender.defender_identity_health_issues_no_open.defender_identity_health_issues_no_open.defender_identity_client",
                new=defender_identity_client,
            ),
        ):
            from prowler.providers.m365.services.defender.defender_identity_health_issues_no_open.defender_identity_health_issues_no_open import (
                defender_identity_health_issues_no_open,
            )
            from prowler.providers.m365.services.defender.defender_service import (
                HealthIssue,
            )

            health_issue_id = "test-health-issue-id-2"
            health_issue_name = "Critical Sensor Health Issue"

            defender_identity_client.health_issues = [
                HealthIssue(
                    id=health_issue_id,
                    display_name=health_issue_name,
                    description="A critical health issue that is open",
                    health_issue_type="global",
                    severity="high",
                    status="open",
                    created_date_time="2024-01-01T00:00:00Z",
                    last_modified_date_time="2024-01-02T00:00:00Z",
                    domain_names=["example.com"],
                    sensor_dns_names=[],
                    issue_type_id="test-issue-type-2",
                    recommendations=["Fix the critical issue immediately"],
                    additional_information=["Additional info about the issue"],
                )
            ]

            check = defender_identity_health_issues_no_open()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Defender for Identity global health issue '{health_issue_name}' is open with high severity."
            )
            assert result[0].resource_id == health_issue_id
            assert result[0].resource_name == health_issue_name
            assert result[0].check_metadata.Severity == "high"

    def test_health_issue_open_medium_severity(self):
        """Test when a health issue is open with medium severity."""
        defender_identity_client = mock.MagicMock()
        defender_identity_client.audited_tenant = "audited_tenant"
        defender_identity_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.defender.defender_identity_health_issues_no_open.defender_identity_health_issues_no_open.defender_identity_client",
                new=defender_identity_client,
            ),
        ):
            from prowler.providers.m365.services.defender.defender_identity_health_issues_no_open.defender_identity_health_issues_no_open import (
                defender_identity_health_issues_no_open,
            )
            from prowler.providers.m365.services.defender.defender_service import (
                HealthIssue,
            )

            health_issue_id = "test-health-issue-id-3"
            health_issue_name = "Medium Severity Sensor Issue"

            defender_identity_client.health_issues = [
                HealthIssue(
                    id=health_issue_id,
                    display_name=health_issue_name,
                    description="A medium severity health issue",
                    health_issue_type="sensor",
                    severity="medium",
                    status="open",
                    created_date_time="2024-01-01T00:00:00Z",
                    last_modified_date_time="2024-01-02T00:00:00Z",
                    domain_names=["example.com"],
                    sensor_dns_names=["sensor2.example.com"],
                    issue_type_id="test-issue-type-3",
                    recommendations=["Review and fix the issue"],
                    additional_information=[],
                )
            ]

            check = defender_identity_health_issues_no_open()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Defender for Identity sensor health issue '{health_issue_name}' is open with medium severity."
            )
            assert result[0].resource_id == health_issue_id
            assert result[0].resource_name == health_issue_name
            assert result[0].check_metadata.Severity == "medium"

    def test_health_issue_open_low_severity(self):
        """Test when a health issue is open with low severity."""
        defender_identity_client = mock.MagicMock()
        defender_identity_client.audited_tenant = "audited_tenant"
        defender_identity_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.defender.defender_identity_health_issues_no_open.defender_identity_health_issues_no_open.defender_identity_client",
                new=defender_identity_client,
            ),
        ):
            from prowler.providers.m365.services.defender.defender_identity_health_issues_no_open.defender_identity_health_issues_no_open import (
                defender_identity_health_issues_no_open,
            )
            from prowler.providers.m365.services.defender.defender_service import (
                HealthIssue,
            )

            health_issue_id = "test-health-issue-id-4"
            health_issue_name = "Low Severity Health Issue"

            defender_identity_client.health_issues = [
                HealthIssue(
                    id=health_issue_id,
                    display_name=health_issue_name,
                    description="A low severity health issue",
                    health_issue_type="global",
                    severity="low",
                    status="open",
                    created_date_time="2024-01-01T00:00:00Z",
                    last_modified_date_time="2024-01-02T00:00:00Z",
                    domain_names=["example.com"],
                    sensor_dns_names=[],
                    issue_type_id="test-issue-type-4",
                    recommendations=["Consider fixing the issue"],
                    additional_information=[],
                )
            ]

            check = defender_identity_health_issues_no_open()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Defender for Identity global health issue '{health_issue_name}' is open with low severity."
            )
            assert result[0].resource_id == health_issue_id
            assert result[0].resource_name == health_issue_name
            assert result[0].check_metadata.Severity == "low"

    def test_multiple_health_issues_mixed_status(self):
        """Test when there are multiple health issues with different statuses."""
        defender_identity_client = mock.MagicMock()
        defender_identity_client.audited_tenant = "audited_tenant"
        defender_identity_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.defender.defender_identity_health_issues_no_open.defender_identity_health_issues_no_open.defender_identity_client",
                new=defender_identity_client,
            ),
        ):
            from prowler.providers.m365.services.defender.defender_identity_health_issues_no_open.defender_identity_health_issues_no_open import (
                defender_identity_health_issues_no_open,
            )
            from prowler.providers.m365.services.defender.defender_service import (
                HealthIssue,
            )

            defender_identity_client.health_issues = [
                HealthIssue(
                    id="issue-1",
                    display_name="Resolved Issue",
                    description="A resolved health issue",
                    health_issue_type="sensor",
                    severity="high",
                    status="closed",
                    created_date_time="2024-01-01T00:00:00Z",
                    last_modified_date_time="2024-01-02T00:00:00Z",
                    domain_names=["example.com"],
                    sensor_dns_names=["sensor1.example.com"],
                    issue_type_id="type-1",
                    recommendations=[],
                    additional_information=[],
                ),
                HealthIssue(
                    id="issue-2",
                    display_name="Open Issue",
                    description="An open health issue",
                    health_issue_type="global",
                    severity="medium",
                    status="open",
                    created_date_time="2024-01-01T00:00:00Z",
                    last_modified_date_time="2024-01-02T00:00:00Z",
                    domain_names=["example.com"],
                    sensor_dns_names=[],
                    issue_type_id="type-2",
                    recommendations=["Fix this issue"],
                    additional_information=[],
                ),
            ]

            check = defender_identity_health_issues_no_open()
            result = check.execute()

            assert len(result) == 2

            # First result should be PASS (resolved issue)
            assert result[0].status == "PASS"
            assert result[0].resource_id == "issue-1"
            assert result[0].resource_name == "Resolved Issue"
            assert (
                result[0].status_extended
                == "Defender for Identity sensor health issue 'Resolved Issue' is resolved."
            )

            # Second result should be FAIL (open issue)
            assert result[1].status == "FAIL"
            assert result[1].resource_id == "issue-2"
            assert result[1].resource_name == "Open Issue"
            assert (
                result[1].status_extended
                == "Defender for Identity global health issue 'Open Issue' is open with medium severity."
            )
            assert result[1].check_metadata.Severity == "medium"

    def test_health_issue_with_unknown_type_and_severity(self):
        """Test when health issue has None/unknown type and severity."""
        defender_identity_client = mock.MagicMock()
        defender_identity_client.audited_tenant = "audited_tenant"
        defender_identity_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.defender.defender_identity_health_issues_no_open.defender_identity_health_issues_no_open.defender_identity_client",
                new=defender_identity_client,
            ),
        ):
            from prowler.providers.m365.services.defender.defender_identity_health_issues_no_open.defender_identity_health_issues_no_open import (
                defender_identity_health_issues_no_open,
            )
            from prowler.providers.m365.services.defender.defender_service import (
                HealthIssue,
            )

            health_issue_id = "test-health-issue-id-5"
            health_issue_name = "Unknown Type Issue"

            defender_identity_client.health_issues = [
                HealthIssue(
                    id=health_issue_id,
                    display_name=health_issue_name,
                    description="A health issue with unknown type and severity",
                    health_issue_type=None,
                    severity=None,
                    status="open",
                    created_date_time="2024-01-01T00:00:00Z",
                    last_modified_date_time="2024-01-02T00:00:00Z",
                    domain_names=[],
                    sensor_dns_names=[],
                    issue_type_id="test-issue-type-5",
                    recommendations=[],
                    additional_information=[],
                )
            ]

            check = defender_identity_health_issues_no_open()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Defender for Identity unknown health issue '{health_issue_name}' is open with unknown severity."
            )
            assert result[0].resource_id == health_issue_id
            assert result[0].resource_name == health_issue_name

    def test_health_issue_status_case_insensitive(self):
        """Test that status comparison is case insensitive (OPEN vs open)."""
        defender_identity_client = mock.MagicMock()
        defender_identity_client.audited_tenant = "audited_tenant"
        defender_identity_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.defender.defender_identity_health_issues_no_open.defender_identity_health_issues_no_open.defender_identity_client",
                new=defender_identity_client,
            ),
        ):
            from prowler.providers.m365.services.defender.defender_identity_health_issues_no_open.defender_identity_health_issues_no_open import (
                defender_identity_health_issues_no_open,
            )
            from prowler.providers.m365.services.defender.defender_service import (
                HealthIssue,
            )

            health_issue_id = "test-health-issue-id-6"
            health_issue_name = "Uppercase Status Issue"

            defender_identity_client.health_issues = [
                HealthIssue(
                    id=health_issue_id,
                    display_name=health_issue_name,
                    description="A health issue with uppercase OPEN status",
                    health_issue_type="sensor",
                    severity="high",
                    status="OPEN",
                    created_date_time="2024-01-01T00:00:00Z",
                    last_modified_date_time="2024-01-02T00:00:00Z",
                    domain_names=["example.com"],
                    sensor_dns_names=["sensor.example.com"],
                    issue_type_id="test-issue-type-6",
                    recommendations=["Fix the issue"],
                    additional_information=[],
                )
            ]

            check = defender_identity_health_issues_no_open()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Defender for Identity sensor health issue '{health_issue_name}' is open with high severity."
            )
            assert result[0].resource_id == health_issue_id

    def test_health_issue_with_empty_status(self):
        """Test when health issue has empty/None status (treated as not open)."""
        defender_identity_client = mock.MagicMock()
        defender_identity_client.audited_tenant = "audited_tenant"
        defender_identity_client.audited_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.defender.defender_identity_health_issues_no_open.defender_identity_health_issues_no_open.defender_identity_client",
                new=defender_identity_client,
            ),
        ):
            from prowler.providers.m365.services.defender.defender_identity_health_issues_no_open.defender_identity_health_issues_no_open import (
                defender_identity_health_issues_no_open,
            )
            from prowler.providers.m365.services.defender.defender_service import (
                HealthIssue,
            )

            health_issue_id = "test-health-issue-id-7"
            health_issue_name = "Empty Status Issue"

            defender_identity_client.health_issues = [
                HealthIssue(
                    id=health_issue_id,
                    display_name=health_issue_name,
                    description="A health issue with empty status",
                    health_issue_type="global",
                    severity="medium",
                    status=None,
                    created_date_time="2024-01-01T00:00:00Z",
                    last_modified_date_time="2024-01-02T00:00:00Z",
                    domain_names=[],
                    sensor_dns_names=[],
                    issue_type_id="test-issue-type-7",
                    recommendations=[],
                    additional_information=[],
                )
            ]

            check = defender_identity_health_issues_no_open()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Defender for Identity global health issue '{health_issue_name}' is resolved."
            )
            assert result[0].resource_id == health_issue_id
            assert result[0].resource_name == health_issue_name
