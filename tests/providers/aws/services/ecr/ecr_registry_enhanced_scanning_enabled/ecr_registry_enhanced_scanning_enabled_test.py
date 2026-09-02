from unittest import mock

from prowler.providers.aws.services.ecr.ecr_service import (
    Registry,
    Repository,
    ScanningRule,
)
from tests.providers.aws.utils import (
    AWS_ACCOUNT_ARN,
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

repository_name = "test_repo"
repository_arn = (
    f"arn:aws:ecr:eu-west-1:{AWS_ACCOUNT_NUMBER}:repository/{repository_name}"
)
registry_arn = (
    f"arn:aws:ecr:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:registry/"
    f"{AWS_ACCOUNT_NUMBER}"
)


def _registry(scan_type, rules, repositories=None, region=AWS_REGION_EU_WEST_1):
    """Build a Registry holding one repository unless told otherwise.

    A registry is per-region, so `region` is a parameter: an account using ECR in more than one
    region has more than one registry, and each carries its own scanning configuration.
    """
    if repositories is None:
        repositories = [
            Repository(
                name=repository_name,
                arn=f"arn:aws:ecr:{region}:{AWS_ACCOUNT_NUMBER}:repository/{repository_name}",
                region=region,
                scan_on_push=True,
                policy="",
                images_details=None,
                lifecycle_policy="",
            )
        ]
    return Registry(
        id=AWS_ACCOUNT_NUMBER,
        arn=f"arn:aws:ecr:{region}:{AWS_ACCOUNT_NUMBER}:registry/{AWS_ACCOUNT_NUMBER}",
        region=region,
        scan_type=scan_type,
        repositories=repositories,
        rules=rules,
    )


class Test_ecr_registry_enhanced_scanning_enabled:
    def test_no_registries(self):
        """Check produces no findings when no registries exist."""
        ecr_client = mock.MagicMock
        ecr_client.registries = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_aws_provider(),
            ),
            mock.patch(
                "prowler.providers.aws.services.ecr.ecr_registry_enhanced_scanning_enabled.ecr_registry_enhanced_scanning_enabled.ecr_client",
                ecr_client,
            ),
        ):
            from prowler.providers.aws.services.ecr.ecr_registry_enhanced_scanning_enabled.ecr_registry_enhanced_scanning_enabled import (
                ecr_registry_enhanced_scanning_enabled,
            )

            check = ecr_registry_enhanced_scanning_enabled()
            result = check.execute()
            assert len(result) == 0

    def test_registry_no_repositories(self):
        """Check skips registries holding no repositories (not in use)."""
        ecr_client = mock.MagicMock
        ecr_client.registries = {}
        ecr_client.registries[AWS_REGION_EU_WEST_1] = _registry(
            "BASIC", [], repositories=[]
        )

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_aws_provider(),
            ),
            mock.patch(
                "prowler.providers.aws.services.ecr.ecr_registry_enhanced_scanning_enabled.ecr_registry_enhanced_scanning_enabled.ecr_client",
                ecr_client,
            ),
        ):
            from prowler.providers.aws.services.ecr.ecr_registry_enhanced_scanning_enabled.ecr_registry_enhanced_scanning_enabled import (
                ecr_registry_enhanced_scanning_enabled,
            )

            check = ecr_registry_enhanced_scanning_enabled()
            result = check.execute()
            assert len(result) == 0

    def test_registry_enhanced_scanning(self):
        """Registry with ENHANCED scan type passes the check."""
        ecr_client = mock.MagicMock
        ecr_client.audited_account_arn = AWS_ACCOUNT_ARN
        ecr_client.registries = {}
        ecr_client.registries[AWS_REGION_EU_WEST_1] = _registry(
            "ENHANCED",
            [
                ScanningRule(
                    scan_frequency="CONTINUOUS_SCAN",
                    scan_filters=[{"filter": "*", "filterType": "WILDCARD"}],
                )
            ],
        )

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_aws_provider(),
            ),
            mock.patch(
                "prowler.providers.aws.services.ecr.ecr_registry_enhanced_scanning_enabled.ecr_registry_enhanced_scanning_enabled.ecr_client",
                ecr_client,
            ),
        ):
            from prowler.providers.aws.services.ecr.ecr_registry_enhanced_scanning_enabled.ecr_registry_enhanced_scanning_enabled import (
                ecr_registry_enhanced_scanning_enabled,
            )

            check = ecr_registry_enhanced_scanning_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"ECR registry {AWS_ACCOUNT_NUMBER} has enhanced scanning enabled."
            )
            assert result[0].resource_id == AWS_ACCOUNT_NUMBER
            assert result[0].resource_arn == registry_arn
            assert result[0].region == AWS_REGION_EU_WEST_1

    def test_registry_basic_scanning(self):
        """Registry with BASIC scan type fails the check."""
        ecr_client = mock.MagicMock
        ecr_client.audited_account_arn = AWS_ACCOUNT_ARN
        ecr_client.registries = {}
        ecr_client.registries[AWS_REGION_EU_WEST_1] = _registry(
            "BASIC",
            [
                ScanningRule(
                    scan_frequency="SCAN_ON_PUSH",
                    scan_filters=[{"filter": "*", "filterType": "WILDCARD"}],
                )
            ],
        )

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_aws_provider(),
            ),
            mock.patch(
                "prowler.providers.aws.services.ecr.ecr_registry_enhanced_scanning_enabled.ecr_registry_enhanced_scanning_enabled.ecr_client",
                ecr_client,
            ),
        ):
            from prowler.providers.aws.services.ecr.ecr_registry_enhanced_scanning_enabled.ecr_registry_enhanced_scanning_enabled import (
                ecr_registry_enhanced_scanning_enabled,
            )

            check = ecr_registry_enhanced_scanning_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"ECR registry {AWS_ACCOUNT_NUMBER} has BASIC scanning enabled instead of enhanced scanning."
            )
            assert result[0].resource_id == AWS_ACCOUNT_NUMBER
            assert result[0].resource_arn == registry_arn
            assert result[0].region == AWS_REGION_EU_WEST_1

    def test_registry_enhanced_scanning_empty_rules(self):
        """ENHANCED scan type with empty rules list.

        An ENHANCED registry with no scanning rules still has the scan type
        set to ENHANCED. The check verifies scan type only, not rules.
        """
        ecr_client = mock.MagicMock
        ecr_client.audited_account_arn = AWS_ACCOUNT_ARN
        ecr_client.registries = {}
        ecr_client.registries[AWS_REGION_EU_WEST_1] = _registry("ENHANCED", [])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_aws_provider(),
            ),
            mock.patch(
                "prowler.providers.aws.services.ecr.ecr_registry_enhanced_scanning_enabled.ecr_registry_enhanced_scanning_enabled.ecr_client",
                ecr_client,
            ),
        ):
            from prowler.providers.aws.services.ecr.ecr_registry_enhanced_scanning_enabled.ecr_registry_enhanced_scanning_enabled import (
                ecr_registry_enhanced_scanning_enabled,
            )

            check = ecr_registry_enhanced_scanning_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"ECR registry {AWS_ACCOUNT_NUMBER} has enhanced scanning enabled."
            )
            assert result[0].resource_id == AWS_ACCOUNT_NUMBER
            assert result[0].resource_arn == registry_arn
            assert result[0].region == AWS_REGION_EU_WEST_1

    def test_registry_scanning_configuration_not_retrieved(self):
        """An unread scan type is MANUAL, never PASS.

        ``_get_registry_scanning_configuration`` leaves ``scan_type`` at
        ``None`` when ``GetRegistryScanningConfiguration`` fails for any
        reason other than the "feature is disabled" ValidationException, and
        when the response carries no ``scanningConfiguration`` at all. An
        unanswered scan type is not evidence that enhanced scanning is on.
        """
        ecr_client = mock.MagicMock
        ecr_client.audited_account_arn = AWS_ACCOUNT_ARN
        ecr_client.registries = {}
        ecr_client.registries[AWS_REGION_EU_WEST_1] = _registry(None, None)

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_aws_provider(),
            ),
            mock.patch(
                "prowler.providers.aws.services.ecr.ecr_registry_enhanced_scanning_enabled.ecr_registry_enhanced_scanning_enabled.ecr_client",
                ecr_client,
            ),
        ):
            from prowler.providers.aws.services.ecr.ecr_registry_enhanced_scanning_enabled.ecr_registry_enhanced_scanning_enabled import (
                ecr_registry_enhanced_scanning_enabled,
            )

            check = ecr_registry_enhanced_scanning_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "MANUAL"
            assert (
                result[0].status_extended
                == f"ECR registry {AWS_ACCOUNT_NUMBER} scanning configuration could not be retrieved, check manually if enhanced scanning is enabled."
            )
            assert result[0].resource_id == AWS_ACCOUNT_NUMBER
            assert result[0].resource_arn == registry_arn
            assert result[0].region == AWS_REGION_EU_WEST_1

    def test_multiple_registries_one_verdict_each(self):
        """Each registry is judged on its own scanning configuration.

        A registry is per-region, so an account using ECR in three regions has three of them. One
        ENHANCED, one BASIC and one unread must yield PASS, FAIL and MANUAL against the matching
        region -- a check that reported only the first registry, or reused one verdict across them,
        would leave the other regions unreported or misreported.
        """
        ecr_client = mock.MagicMock
        ecr_client.audited_account_arn = AWS_ACCOUNT_ARN
        ecr_client.registries = {
            AWS_REGION_EU_WEST_1: _registry(
                "ENHANCED", [], region=AWS_REGION_EU_WEST_1
            ),
            AWS_REGION_US_EAST_1: _registry("BASIC", [], region=AWS_REGION_US_EAST_1),
            "eu-central-1": _registry(None, None, region="eu-central-1"),
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_aws_provider(),
            ),
            mock.patch(
                "prowler.providers.aws.services.ecr.ecr_registry_enhanced_scanning_enabled.ecr_registry_enhanced_scanning_enabled.ecr_client",
                ecr_client,
            ),
        ):
            from prowler.providers.aws.services.ecr.ecr_registry_enhanced_scanning_enabled.ecr_registry_enhanced_scanning_enabled import (
                ecr_registry_enhanced_scanning_enabled,
            )

            check = ecr_registry_enhanced_scanning_enabled()
            result = check.execute()

            assert len(result) == 3
            by_region = {report.region: report for report in result}
            assert set(by_region) == {
                AWS_REGION_EU_WEST_1,
                AWS_REGION_US_EAST_1,
                "eu-central-1",
            }
            assert by_region[AWS_REGION_EU_WEST_1].status == "PASS"
            assert by_region[AWS_REGION_US_EAST_1].status == "FAIL"
            assert by_region["eu-central-1"].status == "MANUAL"
            assert (
                by_region[AWS_REGION_US_EAST_1].status_extended
                == f"ECR registry {AWS_ACCOUNT_NUMBER} has BASIC scanning enabled instead of enhanced scanning."
            )
