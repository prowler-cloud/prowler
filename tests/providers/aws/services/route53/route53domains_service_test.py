from datetime import datetime
from unittest.mock import patch

import botocore

from prowler.providers.aws.services.route53.route53_service import Route53Domains
from tests.providers.aws.utils import AWS_REGION_US_EAST_1, set_mocked_aws_provider

# Mocking Access Analyzer Calls
make_api_call = botocore.client.BaseClient._make_api_call


def mock_make_api_call(self, operation_name, kwarg):
    """We have to mock every AWS API call using Boto3"""
    if operation_name == "ListDomains":
        return {
            "Domains": [
                {
                    "DomainName": "test.domain.com",
                    "AutoRenew": True,
                    "TransferLock": True,
                    "Expiry": datetime(2015, 1, 1),
                },
            ],
            "NextPageMarker": "string",
        }
    if operation_name == "ListTagsForDomain":
        return {
            "TagList": [
                {"Key": "test", "Value": "test"},
            ]
        }
    if operation_name == "GetDomainDetail":
        return {
            "DomainName": "test.domain.com",
            "Nameservers": [
                {
                    "Name": "8.8.8.8",
                    "GlueIps": [],
                },
            ],
            "AutoRenew": True,
            "AdminContact": {},
            "RegistrantContact": {},
            "TechContact": {},
            "AdminPrivacy": True,
            "RegistrantPrivacy": True,
            "TechPrivacy": True,
            "RegistrarName": "string",
            "WhoIsServer": "string",
            "RegistrarUrl": "string",
            "AbuseContactEmail": "string",
            "AbuseContactPhone": "string",
            "RegistryDomainId": "string",
            "CreationDate": datetime(2015, 1, 1),
            "UpdatedDate": datetime(2015, 1, 1),
            "ExpirationDate": datetime(2015, 1, 1),
            "Reseller": "string",
            "DnsSec": "string",
            "StatusList": ["clientTransferProhibited"],
        }

    return make_api_call(self, operation_name, kwarg)


# Patch every AWS call using Boto3 and generate_regional_clients to have 1 client
@patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
class Test_Route53_Service:

    # Test Route53Domains Client
    def test__get_client__(self):
        route53domains = Route53Domains(set_mocked_aws_provider([AWS_REGION_US_EAST_1]))
        assert route53domains.client.__class__.__name__ == "Route53Domains"

    # Test Route53Domains Session
    def test__get_session__(self):
        route53domains = Route53Domains(set_mocked_aws_provider([AWS_REGION_US_EAST_1]))
        assert route53domains.session.__class__.__name__ == "Session"

    # Test Route53Domains Service
    def test__get_service__(self):
        route53domains = Route53Domains(set_mocked_aws_provider([AWS_REGION_US_EAST_1]))
        assert route53domains.service == "route53domains"

    def test__list_domains__(self):
        route53domains = Route53Domains(set_mocked_aws_provider([AWS_REGION_US_EAST_1]))
        domain_name = "test.domain.com"
        assert len(route53domains.domains)
        assert route53domains.domains
        assert route53domains.domains[domain_name]
        assert route53domains.domains[domain_name].name == domain_name
        assert route53domains.domains[domain_name].region == AWS_REGION_US_EAST_1
        assert route53domains.domains[domain_name].admin_privacy
        assert route53domains.domains[domain_name].status_list
        assert len(route53domains.domains[domain_name].status_list) == 1
        assert (
            "clientTransferProhibited"
            in route53domains.domains[domain_name].status_list
        )
        assert route53domains.domains[domain_name].tags == [
            {"Key": "test", "Value": "test"},
        ]
