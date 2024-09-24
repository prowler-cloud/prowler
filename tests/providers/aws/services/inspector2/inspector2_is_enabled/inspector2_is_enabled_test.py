from unittest import mock

from prowler.providers.aws.services.inspector2.inspector2_service import Inspector
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
    set_mocked_aws_provider,
)

FINDING_ARN = (
    "arn:aws:inspector2:us-east-1:123456789012:finding/0e436649379db5f327e3cf5bb4421d76"
)


class Test_inspector2_is_enabled:
    def test_inspector2_disabled(self):
        # Mock the inspector2 client
        inspector2_client = mock.MagicMock
        awslambda_client = mock.MagicMock
        ecr_client = mock.MagicMock
        ec2_client = mock.MagicMock
        ec2_client.provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        ecr_client.provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        awslambda_client.provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        inspector2_client.provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        inspector2_client.audited_account = AWS_ACCOUNT_NUMBER
        inspector2_client.audited_account_arn = (
            f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root"
        )
        inspector2_client.region = AWS_REGION_EU_WEST_1
        inspector2_client.inspectors = [
            Inspector(
                id=AWS_ACCOUNT_NUMBER,
                arn=f"arn:aws:inspector2:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:inspector2",
                status="DISABLED",
                ec2_status="DISABLED",
                ecr_status="DISABLED",
                lambda_status="DISABLED",
                lambda_code_status="DISABLED",
                region=AWS_REGION_EU_WEST_1,
            )
        ]
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.inspector2.inspector2_is_enabled.inspector2_is_enabled.inspector2_client",
                new=inspector2_client,
            ):
                # Test Check
                from prowler.providers.aws.services.inspector2.inspector2_is_enabled.inspector2_is_enabled import (
                    inspector2_is_enabled,
                )

                check = inspector2_is_enabled()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == "Inspector2 is not enabled in this account."
                )
                assert result[0].resource_id == AWS_ACCOUNT_NUMBER
                assert (
                    result[0].resource_arn
                    == f"arn:aws:inspector2:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:inspector2"
                )
                assert result[0].region == AWS_REGION_EU_WEST_1

    def test_all_enabled(self):
        # Mock the inspector2 client
        inspector2_client = mock.MagicMock
        inspector2_client.provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        inspector2_client.audited_account = AWS_ACCOUNT_NUMBER
        inspector2_client.audited_account_arn = (
            f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root"
        )
        inspector2_client.region = AWS_REGION_EU_WEST_1
        inspector2_client.inspectors = [
            Inspector(
                id=AWS_ACCOUNT_NUMBER,
                arn=f"arn:aws:inspector2:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:inspector2",
                status="ENABLED",
                ec2_status="ENABLED",
                ecr_status="ENABLED",
                lambda_status="ENABLED",
                lambda_code_status="ENABLED",
                region=AWS_REGION_EU_WEST_1,
            )
        ]
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.inspector2.inspector2_is_enabled.inspector2_is_enabled.inspector2_client",
                new=inspector2_client,
            ):
                # Test Check
                from prowler.providers.aws.services.inspector2.inspector2_is_enabled.inspector2_is_enabled import (
                    inspector2_is_enabled,
                )

                check = inspector2_is_enabled()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "PASS"
                assert (
                    result[0].status_extended
                    == "Inspector2 is enabled for EC2 instances, ECR container images, Lambda functions and code."
                )
                assert result[0].resource_id == AWS_ACCOUNT_NUMBER
                assert (
                    result[0].resource_arn
                    == f"arn:aws:inspector2:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:inspector2"
                )
                assert result[0].region == AWS_REGION_EU_WEST_1

    def test_all_services_disabled(self):
        inspector2_client = mock.MagicMock()
        inspector2_client.provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        inspector2_client.audited_account = AWS_ACCOUNT_NUMBER
        inspector2_client.audited_account_arn = (
            f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root"
        )
        inspector2_client.region = AWS_REGION_EU_WEST_1
        inspector2_client.inspectors = [
            Inspector(
                id=AWS_ACCOUNT_NUMBER,
                arn=f"arn:aws:inspector2:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:inspector2",
                status="ENABLED",
                ec2_status="DISABLED",
                ecr_status="DISABLED",
                lambda_status="DISABLED",
                lambda_code_status="DISABLED",
                region=AWS_REGION_EU_WEST_1,
            )
        ]
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.inspector2.inspector2_is_enabled.inspector2_is_enabled.inspector2_client",
                new=inspector2_client,
            ):
                # Test Check
                from prowler.providers.aws.services.inspector2.inspector2_is_enabled.inspector2_is_enabled import (
                    inspector2_is_enabled,
                )

                check = inspector2_is_enabled()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == "Inspector2 is not enabled for the following services: EC2, ECR, Lambda, Lambda Code."
                )
                assert result[0].resource_id == AWS_ACCOUNT_NUMBER
                assert (
                    result[0].resource_arn
                    == f"arn:aws:inspector2:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:inspector2"
                )
                assert result[0].region == AWS_REGION_EU_WEST_1

    def test_ec2_disabled(self):
        inspector2_client = mock.MagicMock
        inspector2_client.provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        inspector2_client.audited_account = AWS_ACCOUNT_NUMBER
        inspector2_client.audited_account_arn = (
            f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root"
        )
        inspector2_client.region = AWS_REGION_EU_WEST_1
        inspector2_client.inspectors = [
            Inspector(
                id=AWS_ACCOUNT_NUMBER,
                arn=f"arn:aws:inspector2:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:inspector2",
                status="ENABLED",
                ec2_status="DISABLED",
                ecr_status="ENABLED",
                lambda_status="ENABLED",
                lambda_code_status="ENABLED",
                region=AWS_REGION_EU_WEST_1,
            )
        ]
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.inspector2.inspector2_is_enabled.inspector2_is_enabled.inspector2_client",
                new=inspector2_client,
            ):
                # Test Check
                from prowler.providers.aws.services.inspector2.inspector2_is_enabled.inspector2_is_enabled import (
                    inspector2_is_enabled,
                )

                check = inspector2_is_enabled()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == "Inspector2 is not enabled for the following services: EC2."
                )
                assert result[0].resource_id == AWS_ACCOUNT_NUMBER
                assert (
                    result[0].resource_arn
                    == f"arn:aws:inspector2:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:inspector2"
                )
                assert result[0].region == AWS_REGION_EU_WEST_1

    def test_ecr_disabled(self):
        inspector2_client = mock.MagicMock
        inspector2_client.provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        inspector2_client.audited_account = AWS_ACCOUNT_NUMBER
        inspector2_client.audited_account_arn = (
            f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root"
        )
        inspector2_client.region = AWS_REGION_EU_WEST_1
        inspector2_client.inspectors = [
            Inspector(
                id=AWS_ACCOUNT_NUMBER,
                arn=f"arn:aws:inspector2:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:inspector2",
                status="ENABLED",
                ec2_status="ENABLED",
                ecr_status="DISABLED",
                lambda_status="ENABLED",
                lambda_code_status="ENABLED",
                region=AWS_REGION_EU_WEST_1,
            )
        ]
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.inspector2.inspector2_is_enabled.inspector2_is_enabled.inspector2_client",
                new=inspector2_client,
            ):
                # Test Check
                from prowler.providers.aws.services.inspector2.inspector2_is_enabled.inspector2_is_enabled import (
                    inspector2_is_enabled,
                )

                check = inspector2_is_enabled()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == "Inspector2 is not enabled for the following services: ECR."
                )
                assert result[0].resource_id == AWS_ACCOUNT_NUMBER
                assert (
                    result[0].resource_arn
                    == f"arn:aws:inspector2:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:inspector2"
                )
                assert result[0].region == AWS_REGION_EU_WEST_1

    def test_lambda_disabled(self):
        inspector2_client = mock.MagicMock
        inspector2_client.provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        inspector2_client.audited_account = AWS_ACCOUNT_NUMBER
        inspector2_client.audited_account_arn = (
            f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root"
        )
        inspector2_client.region = AWS_REGION_EU_WEST_1
        inspector2_client.inspectors = [
            Inspector(
                id=AWS_ACCOUNT_NUMBER,
                arn=f"arn:aws:inspector2:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:inspector2",
                status="ENABLED",
                ec2_status="ENABLED",
                ecr_status="ENABLED",
                lambda_status="DISABLED",
                lambda_code_status="ENABLED",
                region=AWS_REGION_EU_WEST_1,
            )
        ]
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.inspector2.inspector2_is_enabled.inspector2_is_enabled.inspector2_client",
                new=inspector2_client,
            ):
                # Test Check
                from prowler.providers.aws.services.inspector2.inspector2_is_enabled.inspector2_is_enabled import (
                    inspector2_is_enabled,
                )

                check = inspector2_is_enabled()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == "Inspector2 is not enabled for the following services: Lambda."
                )
                assert result[0].resource_id == AWS_ACCOUNT_NUMBER
                assert (
                    result[0].resource_arn
                    == f"arn:aws:inspector2:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:inspector2"
                )
                assert result[0].region == AWS_REGION_EU_WEST_1

    def test_lambda_code_disabled(self):
        inspector2_client = mock.MagicMock
        inspector2_client.provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        inspector2_client.audited_account = AWS_ACCOUNT_NUMBER
        inspector2_client.audited_account_arn = (
            f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root"
        )
        inspector2_client.region = AWS_REGION_EU_WEST_1
        inspector2_client.inspectors = [
            Inspector(
                id=AWS_ACCOUNT_NUMBER,
                arn=f"arn:aws:inspector2:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:inspector2",
                status="ENABLED",
                ec2_status="ENABLED",
                ecr_status="ENABLED",
                lambda_status="ENABLED",
                lambda_code_status="DISABLED",
                region=AWS_REGION_EU_WEST_1,
            )
        ]
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.inspector2.inspector2_is_enabled.inspector2_is_enabled.inspector2_client",
                new=inspector2_client,
            ):
                # Test Check
                from prowler.providers.aws.services.inspector2.inspector2_is_enabled.inspector2_is_enabled import (
                    inspector2_is_enabled,
                )

                check = inspector2_is_enabled()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == "Inspector2 is not enabled for the following services: Lambda Code."
                )
                assert result[0].resource_id == AWS_ACCOUNT_NUMBER
                assert (
                    result[0].resource_arn
                    == f"arn:aws:inspector2:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:inspector2"
                )
                assert result[0].region == AWS_REGION_EU_WEST_1

    def test_ec2_ecr_disabled(self):
        inspector2_client = mock.MagicMock
        inspector2_client.provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        inspector2_client.audited_account = AWS_ACCOUNT_NUMBER
        inspector2_client.audited_account_arn = (
            f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root"
        )
        inspector2_client.region = AWS_REGION_EU_WEST_1
        inspector2_client.inspectors = [
            Inspector(
                id=AWS_ACCOUNT_NUMBER,
                arn=f"arn:aws:inspector2:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:inspector2",
                status="ENABLED",
                ec2_status="DISABLED",
                ecr_status="DISABLED",
                lambda_status="ENABLED",
                lambda_code_status="ENABLED",
                region=AWS_REGION_EU_WEST_1,
            )
        ]
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.inspector2.inspector2_is_enabled.inspector2_is_enabled.inspector2_client",
                new=inspector2_client,
            ):
                # Test Check
                from prowler.providers.aws.services.inspector2.inspector2_is_enabled.inspector2_is_enabled import (
                    inspector2_is_enabled,
                )

                check = inspector2_is_enabled()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == "Inspector2 is not enabled for the following services: EC2, ECR."
                )
                assert result[0].resource_id == AWS_ACCOUNT_NUMBER
                assert (
                    result[0].resource_arn
                    == f"arn:aws:inspector2:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:inspector2"
                )
                assert result[0].region == AWS_REGION_EU_WEST_1

    def test_ec2_lambda_disabled(self):
        inspector2_client = mock.MagicMock
        inspector2_client.provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        inspector2_client.audited_account = AWS_ACCOUNT_NUMBER
        inspector2_client.audited_account_arn = (
            f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root"
        )
        inspector2_client.region = AWS_REGION_EU_WEST_1
        inspector2_client.inspectors = [
            Inspector(
                id=AWS_ACCOUNT_NUMBER,
                arn=f"arn:aws:inspector2:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:inspector2",
                status="ENABLED",
                ec2_status="DISABLED",
                ecr_status="ENABLED",
                lambda_status="DISABLED",
                lambda_code_status="ENABLED",
                region=AWS_REGION_EU_WEST_1,
            )
        ]
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.inspector2.inspector2_is_enabled.inspector2_is_enabled.inspector2_client",
                new=inspector2_client,
            ):
                # Test Check
                from prowler.providers.aws.services.inspector2.inspector2_is_enabled.inspector2_is_enabled import (
                    inspector2_is_enabled,
                )

                check = inspector2_is_enabled()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == "Inspector2 is not enabled for the following services: EC2, Lambda."
                )
                assert result[0].resource_id == AWS_ACCOUNT_NUMBER
                assert (
                    result[0].resource_arn
                    == f"arn:aws:inspector2:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:inspector2"
                )
                assert result[0].region == AWS_REGION_EU_WEST_1

    def test_ec2_lambda_code_disabled(self):
        inspector2_client = mock.MagicMock
        inspector2_client.provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        inspector2_client.audited_account = AWS_ACCOUNT_NUMBER
        inspector2_client.audited_account_arn = (
            f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root"
        )
        inspector2_client.region = AWS_REGION_EU_WEST_1
        inspector2_client.inspectors = [
            Inspector(
                id=AWS_ACCOUNT_NUMBER,
                arn=f"arn:aws:inspector2:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:inspector2",
                status="ENABLED",
                ec2_status="DISABLED",
                ecr_status="ENABLED",
                lambda_status="ENABLED",
                lambda_code_status="DISABLED",
                region=AWS_REGION_EU_WEST_1,
            )
        ]
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.inspector2.inspector2_is_enabled.inspector2_is_enabled.inspector2_client",
                new=inspector2_client,
            ):
                # Test Check
                from prowler.providers.aws.services.inspector2.inspector2_is_enabled.inspector2_is_enabled import (
                    inspector2_is_enabled,
                )

                check = inspector2_is_enabled()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == "Inspector2 is not enabled for the following services: EC2, Lambda Code."
                )
                assert result[0].resource_id == AWS_ACCOUNT_NUMBER
                assert (
                    result[0].resource_arn
                    == f"arn:aws:inspector2:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:inspector2"
                )
                assert result[0].region == AWS_REGION_EU_WEST_1

    def test_ecr_lambda_disabled(self):
        inspector2_client = mock.MagicMock
        inspector2_client.provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        inspector2_client.audited_account = AWS_ACCOUNT_NUMBER
        inspector2_client.audited_account_arn = (
            f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root"
        )
        inspector2_client.region = AWS_REGION_EU_WEST_1
        inspector2_client.inspectors = [
            Inspector(
                id=AWS_ACCOUNT_NUMBER,
                arn=f"arn:aws:inspector2:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:inspector2",
                status="ENABLED",
                ec2_status="ENABLED",
                ecr_status="DISABLED",
                lambda_status="DISABLED",
                lambda_code_status="ENABLED",
                region=AWS_REGION_EU_WEST_1,
            )
        ]
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.inspector2.inspector2_is_enabled.inspector2_is_enabled.inspector2_client",
                new=inspector2_client,
            ):
                # Test Check
                from prowler.providers.aws.services.inspector2.inspector2_is_enabled.inspector2_is_enabled import (
                    inspector2_is_enabled,
                )

                check = inspector2_is_enabled()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == "Inspector2 is not enabled for the following services: ECR, Lambda."
                )
                assert result[0].resource_id == AWS_ACCOUNT_NUMBER
                assert (
                    result[0].resource_arn
                    == f"arn:aws:inspector2:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:inspector2"
                )
                assert result[0].region == AWS_REGION_EU_WEST_1

    def test_ecr_lambda_code_disabled(self):
        inspector2_client = mock.MagicMock
        inspector2_client.provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        inspector2_client.audited_account = AWS_ACCOUNT_NUMBER
        inspector2_client.audited_account_arn = (
            f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root"
        )
        inspector2_client.region = AWS_REGION_EU_WEST_1
        inspector2_client.inspectors = [
            Inspector(
                id=AWS_ACCOUNT_NUMBER,
                arn=f"arn:aws:inspector2:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:inspector2",
                status="ENABLED",
                ec2_status="ENABLED",
                ecr_status="DISABLED",
                lambda_status="ENABLED",
                lambda_code_status="DISABLED",
                region=AWS_REGION_EU_WEST_1,
            )
        ]
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.inspector2.inspector2_is_enabled.inspector2_is_enabled.inspector2_client",
                new=inspector2_client,
            ):
                # Test Check
                from prowler.providers.aws.services.inspector2.inspector2_is_enabled.inspector2_is_enabled import (
                    inspector2_is_enabled,
                )

                check = inspector2_is_enabled()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == "Inspector2 is not enabled for the following services: ECR, Lambda Code."
                )
                assert result[0].resource_id == AWS_ACCOUNT_NUMBER
                assert (
                    result[0].resource_arn
                    == f"arn:aws:inspector2:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:inspector2"
                )
                assert result[0].region == AWS_REGION_EU_WEST_1

    def test_lambda_lambda_code_disabled(self):
        inspector2_client = mock.MagicMock
        inspector2_client.provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        inspector2_client.audited_account = AWS_ACCOUNT_NUMBER
        inspector2_client.audited_account_arn = (
            f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root"
        )
        inspector2_client.region = AWS_REGION_EU_WEST_1
        inspector2_client.inspectors = [
            Inspector(
                id=AWS_ACCOUNT_NUMBER,
                arn=f"arn:aws:inspector2:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:inspector2",
                status="ENABLED",
                ec2_status="ENABLED",
                ecr_status="ENABLED",
                lambda_status="DISABLED",
                lambda_code_status="DISABLED",
                region=AWS_REGION_EU_WEST_1,
            )
        ]
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.inspector2.inspector2_is_enabled.inspector2_is_enabled.inspector2_client",
                new=inspector2_client,
            ):
                # Test Check
                from prowler.providers.aws.services.inspector2.inspector2_is_enabled.inspector2_is_enabled import (
                    inspector2_is_enabled,
                )

                check = inspector2_is_enabled()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == "Inspector2 is not enabled for the following services: Lambda, Lambda Code."
                )
                assert result[0].resource_id == AWS_ACCOUNT_NUMBER
                assert (
                    result[0].resource_arn
                    == f"arn:aws:inspector2:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:inspector2"
                )
                assert result[0].region == AWS_REGION_EU_WEST_1

    def test_ec2_ecr_lambda_disabled(self):
        inspector2_client = mock.MagicMock
        inspector2_client.provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        inspector2_client.audited_account = AWS_ACCOUNT_NUMBER
        inspector2_client.audited_account_arn = (
            f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root"
        )
        inspector2_client.region = AWS_REGION_EU_WEST_1
        inspector2_client.inspectors = [
            Inspector(
                id=AWS_ACCOUNT_NUMBER,
                arn=f"arn:aws:inspector2:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:inspector2",
                status="ENABLED",
                ec2_status="DISABLED",
                ecr_status="DISABLED",
                lambda_status="DISABLED",
                lambda_code_status="ENABLED",
                region=AWS_REGION_EU_WEST_1,
            )
        ]
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.inspector2.inspector2_is_enabled.inspector2_is_enabled.inspector2_client",
                new=inspector2_client,
            ):
                # Test Check
                from prowler.providers.aws.services.inspector2.inspector2_is_enabled.inspector2_is_enabled import (
                    inspector2_is_enabled,
                )

                check = inspector2_is_enabled()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == "Inspector2 is not enabled for the following services: EC2, ECR, Lambda."
                )
                assert result[0].resource_id == AWS_ACCOUNT_NUMBER
                assert (
                    result[0].resource_arn
                    == f"arn:aws:inspector2:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:inspector2"
                )
                assert result[0].region == AWS_REGION_EU_WEST_1

    def test_ec2_ecr_lambda_code_disabled(self):
        inspector2_client = mock.MagicMock
        inspector2_client.provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        inspector2_client.audited_account = AWS_ACCOUNT_NUMBER
        inspector2_client.audited_account_arn = (
            f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root"
        )
        inspector2_client.region = AWS_REGION_EU_WEST_1
        inspector2_client.inspectors = [
            Inspector(
                id=AWS_ACCOUNT_NUMBER,
                arn=f"arn:aws:inspector2:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:inspector2",
                status="ENABLED",
                ec2_status="DISABLED",
                ecr_status="DISABLED",
                lambda_status="ENABLED",
                lambda_code_status="DISABLED",
                region=AWS_REGION_EU_WEST_1,
            )
        ]
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.inspector2.inspector2_is_enabled.inspector2_is_enabled.inspector2_client",
                new=inspector2_client,
            ):
                # Test Check
                from prowler.providers.aws.services.inspector2.inspector2_is_enabled.inspector2_is_enabled import (
                    inspector2_is_enabled,
                )

                check = inspector2_is_enabled()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == "Inspector2 is not enabled for the following services: EC2, ECR, Lambda Code."
                )
                assert result[0].resource_id == AWS_ACCOUNT_NUMBER
                assert (
                    result[0].resource_arn
                    == f"arn:aws:inspector2:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:inspector2"
                )
                assert result[0].region == AWS_REGION_EU_WEST_1

    def test_ec2_lambda_lambda_code_disabled(self):
        inspector2_client = mock.MagicMock
        inspector2_client.provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        inspector2_client.audited_account = AWS_ACCOUNT_NUMBER
        inspector2_client.audited_account_arn = (
            f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root"
        )
        inspector2_client.region = AWS_REGION_EU_WEST_1
        inspector2_client.inspectors = [
            Inspector(
                id=AWS_ACCOUNT_NUMBER,
                arn=f"arn:aws:inspector2:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:inspector2",
                status="ENABLED",
                ec2_status="DISABLED",
                ecr_status="ENABLED",
                lambda_status="DISABLED",
                lambda_code_status="DISABLED",
                region=AWS_REGION_EU_WEST_1,
            )
        ]
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.inspector2.inspector2_is_enabled.inspector2_is_enabled.inspector2_client",
                new=inspector2_client,
            ):
                # Test Check
                from prowler.providers.aws.services.inspector2.inspector2_is_enabled.inspector2_is_enabled import (
                    inspector2_is_enabled,
                )

                check = inspector2_is_enabled()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == "Inspector2 is not enabled for the following services: EC2, Lambda, Lambda Code."
                )
                assert result[0].resource_id == AWS_ACCOUNT_NUMBER
                assert (
                    result[0].resource_arn
                    == f"arn:aws:inspector2:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:inspector2"
                )
                assert result[0].region == AWS_REGION_EU_WEST_1

    def test_ecr_lambda_lambda_code_disabled(self):
        inspector2_client = mock.MagicMock
        inspector2_client.provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        inspector2_client.audited_account = AWS_ACCOUNT_NUMBER
        inspector2_client.audited_account_arn = (
            f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root"
        )
        inspector2_client.region = AWS_REGION_EU_WEST_1
        inspector2_client.inspectors = [
            Inspector(
                id=AWS_ACCOUNT_NUMBER,
                arn=f"arn:aws:inspector2:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:inspector2",
                status="ENABLED",
                ec2_status="ENABLED",
                ecr_status="DISABLED",
                lambda_status="DISABLED",
                lambda_code_status="DISABLED",
                region=AWS_REGION_EU_WEST_1,
            )
        ]
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.inspector2.inspector2_is_enabled.inspector2_is_enabled.inspector2_client",
                new=inspector2_client,
            ):
                # Test Check
                from prowler.providers.aws.services.inspector2.inspector2_is_enabled.inspector2_is_enabled import (
                    inspector2_is_enabled,
                )

                check = inspector2_is_enabled()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == "Inspector2 is not enabled for the following services: ECR, Lambda, Lambda Code."
                )
                assert result[0].resource_id == AWS_ACCOUNT_NUMBER
                assert (
                    result[0].resource_arn
                    == f"arn:aws:inspector2:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:inspector2"
                )
                assert result[0].region == AWS_REGION_EU_WEST_1
