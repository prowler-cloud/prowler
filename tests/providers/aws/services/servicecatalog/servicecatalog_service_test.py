from unittest.mock import patch

import botocore
from moto import mock_aws

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
                    "Id": "portfolio-id-test",
                    "ARN": "arn:aws:servicecatalog:eu-west-1:123456789012:portfolio/portfolio-id-test",
                    "DisplayName": "portfolio-name",
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
    elif operation_name == "DescribePortfolio":
        return {
            "Tags": {"tag1": "value1", "tag2": "value2"},
        }
    return make_api_call(self, operation_name, kwarg)


def mock_generate_regional_clients(provider, service):
    regional_client = provider._session.current_session.client(
        service, region_name=AWS_REGION_EU_WEST_1
    )
    regional_client.region = AWS_REGION_EU_WEST_1
    return {AWS_REGION_EU_WEST_1: regional_client}


@patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
@patch(
    "prowler.providers.aws.aws_provider.AwsProvider.generate_regional_clients",
    new=mock_generate_regional_clients,
)
class Test_ServiceCatalog_Service:
    # Test ServiceCatalog Service
    def test_service(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        service_catalog = ServiceCatalog(aws_provider)
        assert service_catalog.service == "servicecatalog"

    # Test ServiceCatalog client
    def test_client(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        service_catalog = ServiceCatalog(aws_provider)
        for reg_client in service_catalog.regional_clients.values():
            assert reg_client.__class__.__name__ == "ServiceCatalog"

    # Test ServiceCatalog session
    def test__get_session__(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        ses = ServiceCatalog(aws_provider)
        assert ses.session.__class__.__name__ == "Session"

    @mock_aws
    # Test ServiceCatalog list portfolios
    def test_list_portfolios(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        service_catalog = ServiceCatalog(aws_provider)
        arn = f"arn:aws:servicecatalog:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:portfolio/portfolio-id-test"
        assert service_catalog.portfolios[arn].name == "portfolio-name"
        assert service_catalog.portfolios[arn].id == "portfolio-id-test"
        assert service_catalog.portfolios[arn].arn == arn
        assert service_catalog.portfolios[arn].region == AWS_REGION_EU_WEST_1

    @mock_aws
    # Test ServiceCatalog describe portfolio shares
    def test_describe_portfolio_shares(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        service_catalog = ServiceCatalog(aws_provider)
        arn = f"arn:aws:servicecatalog:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:portfolio/portfolio-id-test"
        assert len(service_catalog.portfolios[arn].shares) == 4
        assert service_catalog.portfolios[arn].shares[0].accepted
        assert service_catalog.portfolios[arn].shares[0].type == "ACCOUNT"

    @mock_aws
    # Test ServiceCatalog describe portfolio
    def test_describe_portfolio(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        service_catalog = ServiceCatalog(aws_provider)
        arn = f"arn:aws:servicecatalog:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:portfolio/portfolio-id-test"
        assert service_catalog.portfolios[arn].tags == {
            "tag1": "value1",
            "tag2": "value2",
        }
