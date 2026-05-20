from unittest.mock import patch

import botocore
from moto import mock_aws

from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

orig = botocore.client.BaseClient._make_api_call


AGG_ARN_TEMPLATE = (
    "arn:aws:config:{region}:" + AWS_ACCOUNT_NUMBER + ":config-aggregator/{name}"
)


def _aggregator_payload(
    name, region, *, org_aware=True, all_regions=True, aws_regions=None
):
    payload = {
        "ConfigurationAggregatorName": name,
        "ConfigurationAggregatorArn": AGG_ARN_TEMPLATE.format(region=region, name=name),
    }
    if org_aware:
        org_source = {
            "RoleArn": f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:role/AWSConfigRoleForOrganizations",
            "AllAwsRegions": all_regions,
        }
        if not all_regions and aws_regions:
            org_source["AwsRegions"] = aws_regions
        payload["OrganizationAggregationSource"] = org_source
    return payload


def make_mock_no_aggregators_no_admin():
    def _mock(self, operation_name, api_params):
        if operation_name == "DescribeConfigurationAggregators":
            return {"ConfigurationAggregators": []}
        if operation_name == "ListDelegatedAdministrators":
            return {"DelegatedAdministrators": []}
        return orig(self, operation_name, api_params)

    return _mock


def make_mock_aggregator_not_org_aware():
    def _mock(self, operation_name, api_params):
        if operation_name == "DescribeConfigurationAggregators":
            return {
                "ConfigurationAggregators": [
                    _aggregator_payload(
                        "legacy-agg",
                        AWS_REGION_EU_WEST_1,
                        org_aware=False,
                    )
                ]
            }
        if operation_name == "ListDelegatedAdministrators":
            return {"DelegatedAdministrators": []}
        return orig(self, operation_name, api_params)

    return _mock


def make_mock_org_aggregator_not_all_regions_with_admin():
    def _mock(self, operation_name, api_params):
        if operation_name == "DescribeConfigurationAggregators":
            return {
                "ConfigurationAggregators": [
                    _aggregator_payload(
                        "partial-org-agg",
                        AWS_REGION_EU_WEST_1,
                        org_aware=True,
                        all_regions=False,
                        aws_regions=[AWS_REGION_EU_WEST_1],
                    )
                ]
            }
        if operation_name == "ListDelegatedAdministrators":
            return {
                "DelegatedAdministrators": [
                    {
                        "Id": "123456789012",
                        "Arn": f"arn:aws:organizations::{AWS_ACCOUNT_NUMBER}:account/o-abc123/123456789012",
                        "Email": "admin@example.com",
                        "Name": "Security",
                        "Status": "ACTIVE",
                        "JoinedMethod": "CREATED",
                    }
                ]
            }
        return orig(self, operation_name, api_params)

    return _mock


def make_mock_full_pass():
    def _mock(self, operation_name, api_params):
        if operation_name == "DescribeConfigurationAggregators":
            return {
                "ConfigurationAggregators": [
                    _aggregator_payload(
                        "org-aggregator",
                        AWS_REGION_EU_WEST_1,
                        org_aware=True,
                        all_regions=True,
                    )
                ]
            }
        if operation_name == "ListDelegatedAdministrators":
            return {
                "DelegatedAdministrators": [
                    {
                        "Id": "123456789012",
                        "Arn": f"arn:aws:organizations::{AWS_ACCOUNT_NUMBER}:account/o-abc123/123456789012",
                        "Email": "admin@example.com",
                        "Name": "Security",
                        "Status": "ACTIVE",
                        "JoinedMethod": "CREATED",
                    }
                ]
            }
        return orig(self, operation_name, api_params)

    return _mock


def make_mock_access_denied_on_orgs():
    def _mock(self, operation_name, api_params):
        if operation_name == "DescribeConfigurationAggregators":
            return {
                "ConfigurationAggregators": [
                    _aggregator_payload(
                        "org-aggregator",
                        AWS_REGION_EU_WEST_1,
                        org_aware=True,
                        all_regions=True,
                    )
                ]
            }
        if operation_name == "ListDelegatedAdministrators":
            raise botocore.exceptions.ClientError(
                {
                    "Error": {
                        "Code": "AccessDeniedException",
                        "Message": "User is not authorized to perform: organizations:ListDelegatedAdministrators",
                    }
                },
                operation_name,
            )
        return orig(self, operation_name, api_params)

    return _mock


class Test_config_delegated_admin_and_org_aggregator_all_regions:
    @mock_aws
    def test_no_aggregators_no_admin(self):
        """Test when no aggregators exist in any region and no delegated admin is set."""
        with patch(
            "botocore.client.BaseClient._make_api_call",
            new=make_mock_no_aggregators_no_admin(),
        ):
            aws_provider = set_mocked_aws_provider(
                [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
            )

            from prowler.providers.aws.services.config.config_service import Config

            with (
                patch(
                    "prowler.providers.common.provider.Provider.get_global_provider",
                    return_value=aws_provider,
                ),
                patch(
                    "prowler.providers.aws.services.config.config_delegated_admin_and_org_aggregator_all_regions.config_delegated_admin_and_org_aggregator_all_regions.config_client",
                    new=Config(aws_provider),
                ),
            ):
                from prowler.providers.aws.services.config.config_delegated_admin_and_org_aggregator_all_regions.config_delegated_admin_and_org_aggregator_all_regions import (
                    config_delegated_admin_and_org_aggregator_all_regions,
                )

                check = config_delegated_admin_and_org_aggregator_all_regions()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert (
                    "no Organization Aggregator configured in any region"
                    in result[0].status_extended
                )
                assert (
                    "no delegated administrator registered for config.amazonaws.com"
                    in result[0].status_extended
                )

    @mock_aws
    def test_aggregator_not_org_aware(self):
        """Test when an aggregator exists but is not an organization aggregator."""
        with patch(
            "botocore.client.BaseClient._make_api_call",
            new=make_mock_aggregator_not_org_aware(),
        ):
            aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

            from prowler.providers.aws.services.config.config_service import Config

            with (
                patch(
                    "prowler.providers.common.provider.Provider.get_global_provider",
                    return_value=aws_provider,
                ),
                patch(
                    "prowler.providers.aws.services.config.config_delegated_admin_and_org_aggregator_all_regions.config_delegated_admin_and_org_aggregator_all_regions.config_client",
                    new=Config(aws_provider),
                ),
            ):
                from prowler.providers.aws.services.config.config_delegated_admin_and_org_aggregator_all_regions.config_delegated_admin_and_org_aggregator_all_regions import (
                    config_delegated_admin_and_org_aggregator_all_regions,
                )

                check = config_delegated_admin_and_org_aggregator_all_regions()
                result = check.execute()

                eu_west_1_result = None
                for finding in result:
                    if finding.region == AWS_REGION_EU_WEST_1:
                        eu_west_1_result = finding
                        break

                assert eu_west_1_result is not None
                assert eu_west_1_result.status == "FAIL"
                assert (
                    "is not an organization aggregator"
                    in eu_west_1_result.status_extended
                )

    @mock_aws
    def test_org_aggregator_not_all_regions_with_admin(self):
        """Test org aggregator that doesn't cover all AWS regions (delegated admin set)."""
        with patch(
            "botocore.client.BaseClient._make_api_call",
            new=make_mock_org_aggregator_not_all_regions_with_admin(),
        ):
            aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

            from prowler.providers.aws.services.config.config_service import Config

            with (
                patch(
                    "prowler.providers.common.provider.Provider.get_global_provider",
                    return_value=aws_provider,
                ),
                patch(
                    "prowler.providers.aws.services.config.config_delegated_admin_and_org_aggregator_all_regions.config_delegated_admin_and_org_aggregator_all_regions.config_client",
                    new=Config(aws_provider),
                ),
            ):
                from prowler.providers.aws.services.config.config_delegated_admin_and_org_aggregator_all_regions.config_delegated_admin_and_org_aggregator_all_regions import (
                    config_delegated_admin_and_org_aggregator_all_regions,
                )

                check = config_delegated_admin_and_org_aggregator_all_regions()
                result = check.execute()

                eu_west_1_result = None
                for finding in result:
                    if finding.region == AWS_REGION_EU_WEST_1:
                        eu_west_1_result = finding
                        break

                assert eu_west_1_result is not None
                assert eu_west_1_result.status == "FAIL"
                assert (
                    "does not cover all AWS regions" in eu_west_1_result.status_extended
                )

    @mock_aws
    def test_full_pass(self):
        """Test PASS: delegated admin set and org aggregator covering all AWS regions."""
        with patch(
            "botocore.client.BaseClient._make_api_call",
            new=make_mock_full_pass(),
        ):
            aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

            from prowler.providers.aws.services.config.config_service import Config

            with (
                patch(
                    "prowler.providers.common.provider.Provider.get_global_provider",
                    return_value=aws_provider,
                ),
                patch(
                    "prowler.providers.aws.services.config.config_delegated_admin_and_org_aggregator_all_regions.config_delegated_admin_and_org_aggregator_all_regions.config_client",
                    new=Config(aws_provider),
                ),
            ):
                from prowler.providers.aws.services.config.config_delegated_admin_and_org_aggregator_all_regions.config_delegated_admin_and_org_aggregator_all_regions import (
                    config_delegated_admin_and_org_aggregator_all_regions,
                )

                check = config_delegated_admin_and_org_aggregator_all_regions()
                result = check.execute()

                eu_west_1_result = None
                for finding in result:
                    if finding.region == AWS_REGION_EU_WEST_1:
                        eu_west_1_result = finding
                        break

                assert eu_west_1_result is not None
                assert eu_west_1_result.status == "PASS"
                assert (
                    "is an organization aggregator covering all AWS regions"
                    in eu_west_1_result.status_extended
                )
                assert "delegated admin configured" in eu_west_1_result.status_extended
                assert eu_west_1_result.resource_arn == AGG_ARN_TEMPLATE.format(
                    region=AWS_REGION_EU_WEST_1, name="org-aggregator"
                )

    @mock_aws
    def test_access_denied_on_organizations(self):
        """Test that AccessDenied on Organizations is reported as unknown admin state."""
        with patch(
            "botocore.client.BaseClient._make_api_call",
            new=make_mock_access_denied_on_orgs(),
        ):
            aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

            from prowler.providers.aws.services.config.config_service import Config

            with (
                patch(
                    "prowler.providers.common.provider.Provider.get_global_provider",
                    return_value=aws_provider,
                ),
                patch(
                    "prowler.providers.aws.services.config.config_delegated_admin_and_org_aggregator_all_regions.config_delegated_admin_and_org_aggregator_all_regions.config_client",
                    new=Config(aws_provider),
                ),
            ):
                from prowler.providers.aws.services.config.config_delegated_admin_and_org_aggregator_all_regions.config_delegated_admin_and_org_aggregator_all_regions import (
                    config_delegated_admin_and_org_aggregator_all_regions,
                )

                check = config_delegated_admin_and_org_aggregator_all_regions()
                result = check.execute()

                eu_west_1_result = None
                for finding in result:
                    if finding.region == AWS_REGION_EU_WEST_1:
                        eu_west_1_result = finding
                        break

                assert eu_west_1_result is not None
                # The check still runs; aggregator coverage is satisfied but the
                # delegated-admin status is unknown, so it must FAIL.
                assert eu_west_1_result.status == "FAIL"
                assert (
                    "delegated administrator status for config.amazonaws.com could not be determined"
                    in eu_west_1_result.status_extended
                )
