from unittest import mock

from prowler.providers.m365.services.entra.entra_service import (
    ImpactedResource,
    Recommendation,
    RecommendationStatus,
)
from tests.providers.m365.m365_fixtures import DOMAIN, set_mocked_m365_provider


class Test_entra_recommendations_completed:
    def test_no_recommendations(self):
        """
        Test when there are no recommendations:
        The check should return an empty list of findings.
        """
        entra_client = mock.MagicMock()
        entra_client.recommendations = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_recommendations_completed.entra_recommendations_completed.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_recommendations_completed.entra_recommendations_completed import (
                entra_recommendations_completed,
            )

            check = entra_recommendations_completed()
            result = check.execute()

            assert len(result) == 0
            assert result == []

    def test_recommendation_completed_by_system(self):
        """
        Test when a recommendation has completedBySystem status:
        The check should PASS.
        """
        entra_client = mock.MagicMock()

        recommendation = Recommendation(
            id="rec-001",
            display_name="Enable MFA for all users",
            status=RecommendationStatus.COMPLETED_BY_SYSTEM,
            impacted_resources=[],
        )
        entra_client.recommendations = {"rec-001": recommendation}
        entra_client.tenant_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_recommendations_completed.entra_recommendations_completed.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_recommendations_completed.entra_recommendations_completed import (
                entra_recommendations_completed,
            )

            check = entra_recommendations_completed()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Entra recommendation 'Enable MFA for all users' is completed."
            )
            assert result[0].resource_id == "rec-001"
            assert result[0].resource_name == "Enable MFA for all users"
            assert result[0].location == "global"

    def test_recommendation_completed_by_user(self):
        """
        Test when a recommendation has completedByUser status:
        The check should PASS.
        """
        entra_client = mock.MagicMock()

        recommendation = Recommendation(
            id="rec-002",
            display_name="Configure password protection",
            status=RecommendationStatus.COMPLETED_BY_USER,
            impacted_resources=[],
        )
        entra_client.recommendations = {"rec-002": recommendation}
        entra_client.tenant_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_recommendations_completed.entra_recommendations_completed.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_recommendations_completed.entra_recommendations_completed import (
                entra_recommendations_completed,
            )

            check = entra_recommendations_completed()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Entra recommendation 'Configure password protection' is completed."
            )
            assert result[0].resource_id == "rec-002"

    def test_recommendation_active(self):
        """
        Test when a recommendation has active status:
        The check should FAIL.
        """
        entra_client = mock.MagicMock()

        recommendation = Recommendation(
            id="rec-003",
            display_name="Enable security defaults",
            status=RecommendationStatus.ACTIVE,
            impacted_resources=[
                ImpactedResource(
                    id="res-001",
                    display_name="User A",
                    status="active",
                    added_date_time="2025-01-01T00:00:00Z",
                ),
                ImpactedResource(
                    id="res-002",
                    display_name="User B",
                    status="active",
                    added_date_time="2025-01-02T00:00:00Z",
                ),
            ],
        )
        entra_client.recommendations = {"rec-003": recommendation}
        entra_client.tenant_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_recommendations_completed.entra_recommendations_completed.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_recommendations_completed.entra_recommendations_completed import (
                entra_recommendations_completed,
            )

            check = entra_recommendations_completed()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Entra recommendation 'Enable security defaults' is not completed with 2 impacted resources."
            )
            assert result[0].resource_id == "rec-003"
            assert result[0].resource_name == "Enable security defaults"

    def test_recommendation_active_single_resource(self):
        """
        Test when a recommendation has active status with one impacted resource:
        The check should FAIL with singular resource text.
        """
        entra_client = mock.MagicMock()

        recommendation = Recommendation(
            id="rec-004",
            display_name="Review inactive users",
            status=RecommendationStatus.ACTIVE,
            impacted_resources=[
                ImpactedResource(
                    id="res-001",
                    display_name="User A",
                    status="active",
                    added_date_time="2025-01-01T00:00:00Z",
                ),
            ],
        )
        entra_client.recommendations = {"rec-004": recommendation}
        entra_client.tenant_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_recommendations_completed.entra_recommendations_completed.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_recommendations_completed.entra_recommendations_completed import (
                entra_recommendations_completed,
            )

            check = entra_recommendations_completed()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Entra recommendation 'Review inactive users' is not completed with 1 impacted resource."
            )

    def test_recommendation_dismissed(self):
        """
        Test when a recommendation has dismissed status:
        The check should PASS with informational severity.
        """
        entra_client = mock.MagicMock()

        recommendation = Recommendation(
            id="rec-005",
            display_name="Migrate to modern auth",
            status=RecommendationStatus.DISMISSED,
            impacted_resources=[],
        )
        entra_client.recommendations = {"rec-005": recommendation}
        entra_client.tenant_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_recommendations_completed.entra_recommendations_completed.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_recommendations_completed.entra_recommendations_completed import (
                entra_recommendations_completed,
            )

            check = entra_recommendations_completed()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].check_metadata.Severity == "informational"
            assert (
                result[0].status_extended
                == "Entra recommendation 'Migrate to modern auth' has been dismissed."
            )
            assert result[0].resource_id == "rec-005"

    def test_recommendation_postponed(self):
        """
        Test when a recommendation has postponed status:
        The check should FAIL.
        """
        entra_client = mock.MagicMock()

        recommendation = Recommendation(
            id="rec-006",
            display_name="Enable audit logging",
            status=RecommendationStatus.POSTPONED,
            impacted_resources=[],
        )
        entra_client.recommendations = {"rec-006": recommendation}
        entra_client.tenant_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_recommendations_completed.entra_recommendations_completed.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_recommendations_completed.entra_recommendations_completed import (
                entra_recommendations_completed,
            )

            check = entra_recommendations_completed()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Entra recommendation 'Enable audit logging' is not completed with 0 impacted resources."
            )

    def test_multiple_recommendations_mixed_status(self):
        """
        Test with multiple recommendations in different statuses:
        Should return a finding for each recommendation.
        """
        entra_client = mock.MagicMock()

        rec_completed = Recommendation(
            id="rec-010",
            display_name="Enable MFA",
            status=RecommendationStatus.COMPLETED_BY_SYSTEM,
            impacted_resources=[],
        )
        rec_active = Recommendation(
            id="rec-011",
            display_name="Review admin accounts",
            status=RecommendationStatus.ACTIVE,
            impacted_resources=[
                ImpactedResource(
                    id="res-001",
                    display_name="Admin User",
                    status="active",
                    added_date_time="2025-01-01T00:00:00Z",
                ),
            ],
        )
        rec_dismissed = Recommendation(
            id="rec-012",
            display_name="Legacy migration",
            status=RecommendationStatus.DISMISSED,
            impacted_resources=[],
        )
        entra_client.recommendations = {
            "rec-010": rec_completed,
            "rec-011": rec_active,
            "rec-012": rec_dismissed,
        }
        entra_client.tenant_domain = DOMAIN

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(
                "prowler.providers.m365.services.entra.entra_recommendations_completed.entra_recommendations_completed.entra_client",
                new=entra_client,
            ),
        ):
            from prowler.providers.m365.services.entra.entra_recommendations_completed.entra_recommendations_completed import (
                entra_recommendations_completed,
            )

            check = entra_recommendations_completed()
            result = check.execute()

            assert len(result) == 3

            # Completed recommendation
            completed_result = next(
                r for r in result if r.resource_id == "rec-010"
            )
            assert completed_result.status == "PASS"

            # Active recommendation
            active_result = next(
                r for r in result if r.resource_id == "rec-011"
            )
            assert active_result.status == "FAIL"

            # Dismissed recommendation
            dismissed_result = next(
                r for r in result if r.resource_id == "rec-012"
            )
            assert dismissed_result.status == "PASS"
            assert dismissed_result.check_metadata.Severity == "informational"
