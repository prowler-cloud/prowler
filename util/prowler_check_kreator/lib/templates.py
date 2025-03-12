def load_check_template(provider: str, service: str, check_name: str) -> str:
    """Load the template for the check file.

    Args:
        provider (str): The provider of the service.
        service (str): The service to check.
        check_name (str): The name of the check.

    Returns:
        A check template used when the user does not want to generate the check with AI.

    Raises:
        ValueError: If the provider is not implemented yet.
    """
    if provider == "aws":
        return f"""
from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.{service}.{service}_client import {service}_client
from typing import List


class {check_name}(Check):
    def execute(self) -> List[Check_Report_AWS]:
        findings = []
        for <resource_arn>, <resource_to_check> in {service}_client.<resources_dict>.items():
            report = Check_Report_AWS(self.metadata())
            report.region = <resource_to_check>.region
            report.resource_id = <resource_to_check>.name
            report.resource_arn = <resource_arn>
            report.resource_tags = <resource_to_check>.tags
            report.status = "FAIL"
            report.status_extended = f"..."

            if <check_logic>:
                report.status = "PASS"
                report.status_extended = f"..."

            findings.append(report)

        return findings
"""
    else:
        raise ValueError(f"Template for {provider} not implemented yet")


def load_test_template(provider: str, service: str, check_name: str) -> str:
    """Load the template for the test file.

    Args:
        provider: The provider of the service (e.g., "aws").
        service: The service to check (e.g., "s3").
        check_name: The name of the check (e.g., "check_bucket_encryption").

    Returns:
        A test template used when the user does not want to generate the check with AI.

    Raises:
        ValueError: If the template for the given provider is not implemented.
    """
    if provider == "aws":
        return f"""
from unittest import mock

from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import (
    AWS_REGION_EU_WEST_1,
    set_mocked_aws_provider,
)


class Test_{check_name}:
    @mock_aws
    def test_<no_attribute>(self):
        from prowler.providers.aws.services.{service}.{service}_service import <service_class_name>

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.{service}.{check_name}.{check_name}.{service}_client",
            new=<service_class_name>(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.{service}.{check_name}.{check_name} import (
                {check_name},
            )

            check = {check_name}()
            result = check.execute()

            assert len(result) == 0

    @mock_aws
    def test_one_compliant_{service}(self):
        {service}_client = client("{service}", region_name=AWS_REGION_EU_WEST_1)
        # Create a compliant resource

        from prowler.providers.aws.services.{service}.{service}_service import <service_class_name>

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.{service}.{check_name}.{check_name}.{service}_client",
            new=<service_class_name>(aws_provider),
        ):
            from prowler.providers.aws.services.{service}.{check_name}.{check_name} import (
                {check_name},
            )

            check = {check_name}()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].status_extended == "..."
            assert result[0].region == AWS_REGION_EU_WEST_1
            assert result[0].resource_id == <resource>.id
            assert (
                result[0].resource_arn
                == f"arn:(aws_partition):{service}:(region):(account_id):(resource)"
            )
            assert result[0].resource_tags == <resource>.tags
"""
    else:
        raise ValueError(f"Template for {provider} not implemented yet")
