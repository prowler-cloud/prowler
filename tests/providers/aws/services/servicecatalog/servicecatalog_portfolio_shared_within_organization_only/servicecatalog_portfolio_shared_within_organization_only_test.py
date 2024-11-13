from unittest import mock

import botocore
from boto3 import client
from moto import mock_aws

from prowler.providers.aws.services.organizations.organizations_service import (
    Organizations,
)
from prowler.providers.aws.services.servicecatalog.servicecatalog_service import (
    ServiceCatalog,
)
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
    set_mocked_aws_provider,
)

make_api_call = botocore.client.BaseClient._make_api_call


def mock_make_api_call(self, operation_name, kwarg):
    if operation_name == "ListPortfolios":
        return {
            "PortfolioDetails": [
                {
                    "Id": "portfolio-account-test",
                    "ARN": "arn:aws:servicecatalog:eu-west-1:123456789012:portfolio/portfolio-account-test",
                    "DisplayName": "portfolio-account",
                }
            ],
        }
    elif operation_name == "DescribePortfolioShares":
        return {
            "PortfolioShareDetails": [
                {
                    "Type": "ACCOUNT",
                    "Accepted": True,
                }
            ],
        }
    return make_api_call(self, operation_name, kwarg)


def mock_make_api_call_v2(self, operation_name, kwarg):
    if operation_name == "ListPortfolios":
        return {
            "PortfolioDetails": [
                {
                    "Id": "portfolio-org-test",
                    "ARN": "arn:aws:servicecatalog:eu-west-1:123456789012:portfolio/portfolio-org-test",
                    "DisplayName": "portfolio-org",
                }
            ],
        }
    elif operation_name == "DescribePortfolioShares":
        if kwarg["type"] == "ACCOUNT":
            return {
                "PortfolioShareDetails": [
                    {
                        "Type": "ORGANIZATION",
                        "Accepted": True,
                    }
                ],
            }
    return make_api_call(self, operation_name, kwarg)


class Test_servicecatalog_portfolio_shared_within_organization_only:
    def test_no_portfolios(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.servicecatalog.servicecatalog_portfolio_shared_within_organization_only.servicecatalog_portfolio_shared_within_organization_only.servicecatalog_client",
            new=ServiceCatalog(aws_provider),
        ):
            from prowler.providers.aws.services.servicecatalog.servicecatalog_portfolio_shared_within_organization_only.servicecatalog_portfolio_shared_within_organization_only import (
                servicecatalog_portfolio_shared_within_organization_only,
            )

            check = servicecatalog_portfolio_shared_within_organization_only()
            result = check.execute()
            assert len(result) == 0

    @mock_aws
    @mock.patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
    def test_organizations_not_active(self):
        client("servicecatalog", region_name=AWS_REGION_EU_WEST_1)
        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1], create_default_organization=False
        )

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.servicecatalog.servicecatalog_portfolio_shared_within_organization_only.servicecatalog_portfolio_shared_within_organization_only.servicecatalog_client",
            new=ServiceCatalog(aws_provider),
        ), mock.patch(
            "prowler.providers.aws.services.servicecatalog.servicecatalog_portfolio_shared_within_organization_only.servicecatalog_portfolio_shared_within_organization_only.organizations_client",
            new=Organizations(aws_provider),
        ):
            from prowler.providers.aws.services.servicecatalog.servicecatalog_portfolio_shared_within_organization_only.servicecatalog_portfolio_shared_within_organization_only import (
                servicecatalog_portfolio_shared_within_organization_only,
            )

            check = servicecatalog_portfolio_shared_within_organization_only()
            result = check.execute()
            assert len(result) == 0

    @mock_aws
    @mock.patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
    def test_portfolio_share_account(self):
        client("servicecatalog", region_name=AWS_REGION_EU_WEST_1)
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        conn = client("organizations")
        conn.create_organization()

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.servicecatalog.servicecatalog_portfolio_shared_within_organization_only.servicecatalog_portfolio_shared_within_organization_only.servicecatalog_client",
            new=ServiceCatalog(aws_provider),
        ), mock.patch(
            "prowler.providers.aws.services.servicecatalog.servicecatalog_portfolio_shared_within_organization_only.servicecatalog_portfolio_shared_within_organization_only.organizations_client",
            new=Organizations(aws_provider),
        ):
            from prowler.providers.aws.services.servicecatalog.servicecatalog_portfolio_shared_within_organization_only.servicecatalog_portfolio_shared_within_organization_only import (
                servicecatalog_portfolio_shared_within_organization_only,
            )

            check = servicecatalog_portfolio_shared_within_organization_only()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "ServiceCatalog Portfolio portfolio-account is shared with an account."
            )
            assert result[0].resource_id == "portfolio-account-test"
            assert (
                result[0].resource_arn
                == f"arn:aws:servicecatalog:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:portfolio/portfolio-account-test"
            )
            assert result[0].region == AWS_REGION_EU_WEST_1

    @mock_aws
    @mock.patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call_v2)
    def test_portfolio_share_organization(self):
        client("servicecatalog", region_name=AWS_REGION_EU_WEST_1)
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        conn = client("organizations")
        conn.create_organization()

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.servicecatalog.servicecatalog_portfolio_shared_within_organization_only.servicecatalog_portfolio_shared_within_organization_only.servicecatalog_client",
            new=ServiceCatalog(aws_provider),
        ), mock.patch(
            "prowler.providers.aws.services.servicecatalog.servicecatalog_portfolio_shared_within_organization_only.servicecatalog_portfolio_shared_within_organization_only.organizations_client",
            new=Organizations(aws_provider),
        ):
            from prowler.providers.aws.services.servicecatalog.servicecatalog_portfolio_shared_within_organization_only.servicecatalog_portfolio_shared_within_organization_only import (
                servicecatalog_portfolio_shared_within_organization_only,
            )

            check = servicecatalog_portfolio_shared_within_organization_only()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "ServiceCatalog Portfolio portfolio-org is shared within your AWS Organization."
            )
            assert result[0].resource_id == "portfolio-org-test"
            assert (
                result[0].resource_arn
                == f"arn:aws:servicecatalog:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:portfolio/portfolio-org-test"
            )
            assert result[0].region == AWS_REGION_EU_WEST_1
