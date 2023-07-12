from datetime import datetime
from unittest.mock import patch

import botocore
from boto3 import session

from prowler.providers.aws.lib.audit_info.audit_info import AWS_Audit_Info
from prowler.providers.aws.services.route53.route53_service import Route53Domains

# Mock Test Region
AWS_REGION = "us-east-1"

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
    # Mocked Audit Info
    def set_mocked_audit_info(self):
        audit_info = AWS_Audit_Info(
            session_config=None,
            original_session=None,
            audit_session=session.Session(
                profile_name=None,
                botocore_session=None,
            ),
            audited_account=None,
            audited_account_arn=None,
            audited_user_id=None,
            audited_partition="aws",
            audited_identity_arn=None,
            profile=None,
            profile_region=AWS_REGION,
            credentials=None,
            assumed_role_info=None,
            audited_regions=None,
            organizations_metadata=None,
            audit_resources=None,
            mfa_enabled=False,
        )
        return audit_info

    # Test Route53Domains Client
    def test__get_client__(self):
        route53domains = Route53Domains(self.set_mocked_audit_info())
        assert route53domains.client.__class__.__name__ == "Route53Domains"

    # Test Route53Domains Session
    def test__get_session__(self):
        route53domains = Route53Domains(self.set_mocked_audit_info())
        assert route53domains.session.__class__.__name__ == "Session"

    # Test Route53Domains Service
    def test__get_service__(self):
        route53domains = Route53Domains(self.set_mocked_audit_info())
        assert route53domains.service == "route53domains"

    def test__list_domains__(self):
        route53domains = Route53Domains(self.set_mocked_audit_info())
        domain_name = "test.domain.com"
        assert len(route53domains.domains)
        assert route53domains.domains
        assert route53domains.domains[domain_name]
        assert route53domains.domains[domain_name].name == domain_name
        assert route53domains.domains[domain_name].region == AWS_REGION
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
