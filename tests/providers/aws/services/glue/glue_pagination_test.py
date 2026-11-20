from boto3 import client
from botocore.stub import Stubber
from moto import mock_aws
from pytest import mark

from prowler.providers.aws.services.glue.glue_service import Glue
from tests.providers.aws.utils import AWS_ACCOUNT_NUMBER, AWS_REGION_US_EAST_1


def _inventory():
    glue = Glue.__new__(Glue)
    glue.audited_account = AWS_ACCOUNT_NUMBER
    glue.audited_partition = "aws"
    glue.audit_resources = []
    glue.tables = []
    glue.ml_transforms = {}
    regional_client = client("glue", region_name=AWS_REGION_US_EAST_1)
    regional_client.region = AWS_REGION_US_EAST_1
    return glue, regional_client


def _resource(operation, name):
    if operation == "search_tables":
        return {
            "Name": name,
            "DatabaseName": "database",
            "CatalogId": AWS_ACCOUNT_NUMBER,
        }
    return {
        "Name": name,
        "TransformId": name,
        "TransformEncryption": {
            "MlUserDataEncryption": {"MlUserDataEncryptionMode": "DISABLED"}
        },
    }


@mark.parametrize(
    "operation,method,result_key",
    [
        ("search_tables", "_search_tables", "TableList"),
        ("get_ml_transforms", "_get_ml_transforms", "Transforms"),
    ],
)
class Test_Glue_Pagination:
    """Exercise real Glue clients with synthetic, token-validated responses."""

    @mark.parametrize("empty_first_page", [False, True])
    @mark.parametrize("filtered", [False, True])
    @mock_aws
    def test_collects_later_pages(
        self, operation, method, result_key, empty_first_page, filtered
    ):
        """Keep fetching through empty or filtered pages to the final resource."""
        glue, regional_client = _inventory()
        resource_type = (
            "table/database" if operation == "search_tables" else "mlTransform"
        )
        expected_arn = f"arn:aws:glue:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:{resource_type}/later"
        if filtered:
            glue.audit_resources = [expected_arn]

        with Stubber(regional_client) as stubber:
            stubber.add_response(
                operation,
                {
                    result_key: (
                        [] if empty_first_page else [_resource(operation, "first")]
                    ),
                    "NextToken": "second-page",
                },
                {},
            )
            stubber.add_response(
                operation,
                {result_key: [], "NextToken": "last-page"},
                {"NextToken": "second-page"},
            )
            stubber.add_response(
                operation,
                {result_key: [_resource(operation, "later")]},
                {"NextToken": "last-page"},
            )
            getattr(glue, method)(regional_client)
            resources = (
                glue.tables
                if operation == "search_tables"
                else list(glue.ml_transforms.values())
            )
            expected_names = (
                ["later"] if filtered or empty_first_page else ["first", "later"]
            )
            assert [resource.name for resource in resources] == expected_names
            assert resources[-1].arn == expected_arn
            assert resources[-1].region == AWS_REGION_US_EAST_1
            if operation == "search_tables":
                assert resources[-1].catalog == AWS_ACCOUNT_NUMBER
                assert resources[-1].database == "database"
            else:
                assert resources[-1].user_data_encryption == "DISABLED"
            stubber.assert_no_pending_responses()

    @mock_aws
    def test_empty_inventory(self, operation, method, result_key):
        """Stop after an empty final page without requesting a token."""
        glue, regional_client = _inventory()
        with Stubber(regional_client) as stubber:
            stubber.add_response(operation, {result_key: []}, {})
            getattr(glue, method)(regional_client)
            assert glue.tables == []
            assert glue.ml_transforms == {}
            stubber.assert_no_pending_responses()

    @mock_aws
    def test_preserves_resources_when_later_page_fails(
        self, operation, method, result_key
    ):
        """Keep earlier inventory while retaining existing API error handling."""
        glue, regional_client = _inventory()
        with Stubber(regional_client) as stubber:
            stubber.add_response(
                operation,
                {result_key: [_resource(operation, "first")], "NextToken": "next"},
                {},
            )
            stubber.add_client_error(
                operation,
                service_error_code="AccessDeniedException",
                expected_params={"NextToken": "next"},
            )
            getattr(glue, method)(regional_client)
            resources = (
                glue.tables
                if operation == "search_tables"
                else list(glue.ml_transforms.values())
            )
            assert [resource.name for resource in resources] == ["first"]
            stubber.assert_no_pending_responses()
