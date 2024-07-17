from io import StringIO
from os import path
from pathlib import Path

import boto3
from moto import mock_aws

from prowler.lib.outputs.csv.models import CSV
from prowler.providers.aws.lib.s3.s3 import S3
from tests.lib.outputs.fixtures.fixtures import generate_finding_output
from tests.providers.aws.utils import AWS_REGION_US_EAST_1

ACTUAL_DIRECTORY = Path(path.dirname(path.realpath(__file__)))
FIXTURES_DIR_NAME = "fixtures"
S3_BUCKET_NAME = "test_bucket"
OUTPUT_MODE_CSV = "csv"
OUTPUT_MODE_JSON_OCSF = "json-ocsf"
OUTPUT_MODE_JSON_ASFF = "json-asff"
OUTPUT_MODE_HTML = "html"
OUTPUT_MODE_CIS_1_4_AWS = "cis_1.4_aws"


class TestS3:
    @mock_aws
    def test_send_no_outputs(self):
        current_session = boto3.session.Session(region_name=AWS_REGION_US_EAST_1)
        s3 = S3(
            session=current_session,
            bucket_name=S3_BUCKET_NAME,
            output_directory=f"{ACTUAL_DIRECTORY}/{FIXTURES_DIR_NAME}",
        )
        assert s3.send_to_bucket({}) == {"success": [], "failure": []}

    @mock_aws
    def test_send_to_s3_bucket_csv_without_file_descriptor(self):

        findings = [generate_finding_output()]

        output = CSV(findings)
        # TODO(PRWLR-4185): this should be changed to use a setter in the Output class
        output._file_descriptor = StringIO()

        current_session = boto3.session.Session(region_name=AWS_REGION_US_EAST_1)
        current_session.client("s3")

        output_directory = f"{ACTUAL_DIRECTORY}/{FIXTURES_DIR_NAME}"

        s3 = S3(
            session=current_session,
            bucket_name=S3_BUCKET_NAME,
            output_directory=output_directory,
        )

        csv = CSV(
            findings=[
                generate_finding_output(
                    status="PASS",
                    status_extended="status-extended",
                    resource_uid="resource-123",
                    resource_name="Example Resource",
                    resource_details="Detailed information about the resource",
                    resource_tags="tag1,tag2",
                    partition="aws",
                    description="Description of the finding",
                    risk="High",
                    related_url="http://example.com",
                    remediation_recommendation_text="Recommendation text",
                    remediation_recommendation_url="http://example.com/remediation",
                    remediation_code_nativeiac="native-iac-code",
                    remediation_code_terraform="terraform-code",
                    remediation_code_other="other-code",
                    remediation_code_cli="cli-code",
                    compliance={"compliance_key": "compliance_value"},
                    categories="category1,category2",
                    depends_on="dependency",
                    related_to="related finding",
                    notes="Notes about the finding",
                )
            ],
            create_file_descriptor=True,
        )
        assert s3.send_to_bucket(outputs={"regular": [csv]}) == 1

        # assert (
        #     s3_client.get_object(
        #         Bucket=S3_BUCKET_NAME,
        #         Key=object_name,
        #     )["ContentType"]
        #     == "binary/octet-stream"
        # )

    # @mock_aws
    # def test_send_to_s3_bucket_json_ocsf(self):
    #     # Mock Audit Info
    #     provider = MagicMock()

    #     # Create mock session
    #     provider.current_session = boto3.session.Session(
    #         region_name=AWS_REGION_US_EAST_1
    #     )
    #     provider.identity.account = AWS_ACCOUNT_NUMBER

    #     # Create mock bucket
    #     client = provider.current_session.client("s3")
    #     client.create_bucket(Bucket=S3_BUCKET_NAME)

    #     # Mocked CSV output file
    #     output_directory = f"{ACTUAL_DIRECTORY}/{FIXTURES_DIR_NAME}"
    #     filename = f"prowler-output-{provider.identity.account}"

    #     # Send mock CSV file to mock S3 Bucket
    #     send_to_s3_bucket(
    #         filename,
    #         output_directory,
    #         OUTPUT_MODE_JSON_OCSF,
    #         S3_BUCKET_NAME,
    #         provider.current_session,
    #     )

    #     bucket_directory = get_s3_object_path(output_directory)
    #     object_name = f"{bucket_directory}/{OUTPUT_MODE_JSON_OCSF}/{filename}{json_ocsf_file_suffix}"

    #     assert (
    #         client.get_object(
    #             Bucket=S3_BUCKET_NAME,
    #             Key=object_name,
    #         )["ContentType"]
    #         == "binary/octet-stream"
    #     )

    # @mock_aws
    # def test_send_to_s3_bucket_json_asff(self):
    #     # Mock Audit Info
    #     provider = MagicMock()

    #     # Create mock session
    #     provider.current_session = boto3.session.Session(
    #         region_name=AWS_REGION_US_EAST_1
    #     )
    #     provider.identity.account = AWS_ACCOUNT_NUMBER

    #     # Create mock bucket
    #     client = provider.current_session.client("s3")
    #     client.create_bucket(Bucket=S3_BUCKET_NAME)

    #     # Mocked CSV output file
    #     output_directory = f"{ACTUAL_DIRECTORY}/{FIXTURES_DIR_NAME}"
    #     filename = f"prowler-output-{provider.identity.account}"

    #     # Send mock CSV file to mock S3 Bucket
    #     send_to_s3_bucket(
    #         filename,
    #         output_directory,
    #         OUTPUT_MODE_JSON_ASFF,
    #         S3_BUCKET_NAME,
    #         provider.current_session,
    #     )

    #     bucket_directory = get_s3_object_path(output_directory)
    #     object_name = f"{bucket_directory}/{OUTPUT_MODE_JSON_ASFF}/{filename}{json_asff_file_suffix}"

    #     assert (
    #         client.get_object(
    #             Bucket=S3_BUCKET_NAME,
    #             Key=object_name,
    #         )["ContentType"]
    #         == "binary/octet-stream"
    #     )

    # @mock_aws
    # def test_send_to_s3_bucket_html(self):
    #     # Mock Audit Info
    #     provider = MagicMock()

    #     # Create mock session
    #     provider.current_session = boto3.session.Session(
    #         region_name=AWS_REGION_US_EAST_1
    #     )
    #     provider.identity.account = AWS_ACCOUNT_NUMBER

    #     # Create mock bucket
    #     client = provider.current_session.client("s3")
    #     client.create_bucket(Bucket=S3_BUCKET_NAME)

    #     # Mocked CSV output file
    #     output_directory = f"{ACTUAL_DIRECTORY}/{FIXTURES_DIR_NAME}"
    #     filename = f"prowler-output-{provider.identity.account}"

    #     # Send mock CSV file to mock S3 Bucket
    #     send_to_s3_bucket(
    #         filename,
    #         output_directory,
    #         OUTPUT_MODE_HTML,
    #         S3_BUCKET_NAME,
    #         provider.current_session,
    #     )

    #     bucket_directory = get_s3_object_path(output_directory)
    #     object_name = (
    #         f"{bucket_directory}/{OUTPUT_MODE_HTML}/{filename}{html_file_suffix}"
    #     )

    #     assert (
    #         client.get_object(
    #             Bucket=S3_BUCKET_NAME,
    #             Key=object_name,
    #         )["ContentType"]
    #         == "binary/octet-stream"
    #     )

    # @mock_aws
    # def test_send_to_s3_bucket_compliance(self):
    #     # Mock Audit Info
    #     provider = MagicMock()

    #     # Create mock session
    #     provider.current_session = boto3.session.Session(
    #         region_name=AWS_REGION_US_EAST_1
    #     )
    #     provider.identity.account = AWS_ACCOUNT_NUMBER

    #     # Create mock bucket
    #     client = provider.current_session.client("s3")
    #     client.create_bucket(Bucket=S3_BUCKET_NAME)

    #     # Mocked CSV output file
    #     output_directory = f"{ACTUAL_DIRECTORY}/{FIXTURES_DIR_NAME}"
    #     filename = f"prowler-output-{provider.identity.account}"

    #     # Send mock CSV file to mock S3 Bucket
    #     send_to_s3_bucket(
    #         filename,
    #         output_directory,
    #         OUTPUT_MODE_CIS_1_4_AWS,
    #         S3_BUCKET_NAME,
    #         provider.current_session,
    #     )

    #     bucket_directory = get_s3_object_path(output_directory)
    #     object_name = f"{bucket_directory}/compliance/{filename}_{OUTPUT_MODE_CIS_1_4_AWS}{csv_file_suffix}"

    #     assert (
    #         client.get_object(
    #             Bucket=S3_BUCKET_NAME,
    #             Key=object_name,
    #         )["ContentType"]
    #         == "binary/octet-stream"
    #     )

    # def test_get_s3_object_path_with_prowler(self):
    #     output_directory = "/Users/admin/prowler/"
    #     assert (
    #         get_s3_object_path(output_directory)
    #         == output_directory.partition("prowler/")[-1]
    #     )

    # def test_get_s3_object_path_without_prowler(self):
    #     output_directory = "/Users/admin/"
    #     assert get_s3_object_path(output_directory) == output_directory
