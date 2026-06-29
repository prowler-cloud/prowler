from os import path
from pathlib import Path
from unittest import mock

from boto3 import resource
from moto import mock_aws

from tests.providers.aws.utils import (
    AWS_REGION_EU_WEST_1,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

EXAMPLE_AMI_ID = "ami-12c6146b"

ACTUAL_DIRECTORY = Path(path.dirname(path.realpath(__file__)))
FIXTURES_DIR_NAME = "fixtures"


class Test_ec2_instance_secrets_user_data:
    @mock_aws
    def test_no_ec2(self):
        from prowler.providers.aws.services.ec2.ec2_service import EC2

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.ec2.ec2_instance_secrets_user_data.ec2_instance_secrets_user_data.ec2_client",
                new=EC2(aws_provider),
            ),
        ):
            # Test Check
            from prowler.providers.aws.services.ec2.ec2_instance_secrets_user_data.ec2_instance_secrets_user_data import (
                ec2_instance_secrets_user_data,
            )

            check = ec2_instance_secrets_user_data()
            result = check.execute()

            assert len(result) == 0

    @mock_aws
    def test_one_ec2_with_no_secrets(self):
        ec2 = resource("ec2", region_name=AWS_REGION_US_EAST_1)
        instance = ec2.create_instances(
            ImageId=EXAMPLE_AMI_ID,
            MinCount=1,
            MaxCount=1,
            UserData="This is some user_data",
        )[0]

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.ec2.ec2_instance_secrets_user_data.ec2_instance_secrets_user_data.ec2_client",
                new=EC2(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.ec2.ec2_instance_secrets_user_data.ec2_instance_secrets_user_data import (
                ec2_instance_secrets_user_data,
            )

            check = ec2_instance_secrets_user_data()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"No secrets found in EC2 instance {instance.id} User Data."
            )
            assert result[0].resource_id == instance.id
            assert (
                result[0].resource_arn
                == f"arn:{aws_provider.identity.partition}:ec2:{AWS_REGION_US_EAST_1}:{aws_provider.identity.account}:instance/{instance.id}"
            )
            assert result[0].resource_tags is None
            assert result[0].region == AWS_REGION_US_EAST_1

    @mock_aws
    def test_one_ec2_with_secrets(self):
        ec2 = resource("ec2", region_name=AWS_REGION_US_EAST_1)
        instance = ec2.create_instances(
            ImageId=EXAMPLE_AMI_ID,
            MinCount=1,
            MaxCount=1,
            UserData='DB_PASSWORD="Tr0ub4dor3xKq9vLmZ"',
        )[0]

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.ec2.ec2_instance_secrets_user_data.ec2_instance_secrets_user_data.ec2_client",
                new=EC2(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.ec2.ec2_instance_secrets_user_data.ec2_instance_secrets_user_data import (
                ec2_instance_secrets_user_data,
            )

            check = ec2_instance_secrets_user_data()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Potential secret found in EC2 instance {instance.id} User Data -> Generic Password on line 1."
            )
            assert result[0].resource_id == instance.id
            assert (
                result[0].resource_arn
                == f"arn:{aws_provider.identity.partition}:ec2:{AWS_REGION_US_EAST_1}:{aws_provider.identity.account}:instance/{instance.id}"
            )
            assert result[0].resource_tags is None
            assert result[0].region == AWS_REGION_US_EAST_1

    @mock_aws
    def test_one_ec2_with_secrets_other_case(self):
        ec2 = resource("ec2", region_name=AWS_REGION_US_EAST_1)
        instance = ec2.create_instances(
            ImageId=EXAMPLE_AMI_ID,
            MinCount=1,
            MaxCount=1,
            UserData="MYSQL_ALLOW_EMPTY_PASSWORD: 'yes'",
        )[0]

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )

        ec2_client = EC2(aws_provider)

        ec2_client.audit_config = {
            "secrets_ignore_patterns": [".*_ALLOW_EMPTY_PASSWORD.*"]
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.ec2.ec2_instance_secrets_user_data.ec2_instance_secrets_user_data.ec2_client",
                new=ec2_client,
            ),
        ):
            from prowler.providers.aws.services.ec2.ec2_instance_secrets_user_data.ec2_instance_secrets_user_data import (
                ec2_instance_secrets_user_data,
            )

            check = ec2_instance_secrets_user_data()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"No secrets found in EC2 instance {instance.id} User Data."
            )
            assert result[0].resource_id == instance.id
            assert (
                result[0].resource_arn
                == f"arn:{aws_provider.identity.partition}:ec2:{AWS_REGION_US_EAST_1}:{aws_provider.identity.account}:instance/{instance.id}"
            )
            assert result[0].resource_tags is None
            assert result[0].region == AWS_REGION_US_EAST_1

    @mock_aws
    def test_one_ec2_file_with_secrets(self):
        # Include launch_configurations to check
        f = open(
            f"{ACTUAL_DIRECTORY}/{FIXTURES_DIR_NAME}/fixture",
            "r",
        )
        secrets = f.read()
        ec2 = resource("ec2", region_name=AWS_REGION_US_EAST_1)
        instance = ec2.create_instances(
            ImageId=EXAMPLE_AMI_ID, MinCount=1, MaxCount=1, UserData=secrets
        )[0]

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.ec2.ec2_instance_secrets_user_data.ec2_instance_secrets_user_data.ec2_client",
                new=EC2(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.ec2.ec2_instance_secrets_user_data.ec2_instance_secrets_user_data import (
                ec2_instance_secrets_user_data,
            )

            check = ec2_instance_secrets_user_data()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Potential secret found in EC2 instance {instance.id} User Data -> Generic Password on line 1, JSON Web Token (base64url-encoded) on line 3, Generic Password on line 4."
            )
            assert result[0].resource_id == instance.id
            assert (
                result[0].resource_arn
                == f"arn:{aws_provider.identity.partition}:ec2:{AWS_REGION_US_EAST_1}:{aws_provider.identity.account}:instance/{instance.id}"
            )
            assert result[0].resource_tags is None
            assert result[0].region == AWS_REGION_US_EAST_1

    @mock_aws
    def test_one_launch_configurations_without_user_data(self):
        ec2 = resource("ec2", region_name=AWS_REGION_US_EAST_1)
        instance = ec2.create_instances(
            ImageId=EXAMPLE_AMI_ID, MinCount=1, MaxCount=1, UserData=""
        )[0]

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.ec2.ec2_instance_secrets_user_data.ec2_instance_secrets_user_data.ec2_client",
                new=EC2(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.ec2.ec2_instance_secrets_user_data.ec2_instance_secrets_user_data import (
                ec2_instance_secrets_user_data,
            )

            check = ec2_instance_secrets_user_data()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"No secrets found in EC2 instance {instance.id} since User Data is empty."
            )
            assert result[0].resource_id == instance.id
            assert (
                result[0].resource_arn
                == f"arn:{aws_provider.identity.partition}:ec2:{AWS_REGION_US_EAST_1}:{aws_provider.identity.account}:instance/{instance.id}"
            )
            assert result[0].resource_tags is None
            assert result[0].region == AWS_REGION_US_EAST_1

    @mock_aws
    def test_one_ec2_file_with_secrets_gzip(self):
        # Include launch_configurations to check
        f = open(
            f"{ACTUAL_DIRECTORY}/{FIXTURES_DIR_NAME}/fixture.gz",
            "rb",
        )
        secrets = f.read()
        ec2 = resource("ec2", region_name=AWS_REGION_US_EAST_1)
        instance = ec2.create_instances(
            ImageId=EXAMPLE_AMI_ID, MinCount=1, MaxCount=1, UserData=secrets
        )[0]

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.ec2.ec2_instance_secrets_user_data.ec2_instance_secrets_user_data.ec2_client",
                new=EC2(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.ec2.ec2_instance_secrets_user_data.ec2_instance_secrets_user_data import (
                ec2_instance_secrets_user_data,
            )

            check = ec2_instance_secrets_user_data()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Potential secret found in EC2 instance {instance.id} User Data -> Generic Password on line 1, JSON Web Token (base64url-encoded) on line 3, Generic Password on line 4."
            )
            assert result[0].resource_id == instance.id
            assert (
                result[0].resource_arn
                == f"arn:{aws_provider.identity.partition}:ec2:{AWS_REGION_US_EAST_1}:{aws_provider.identity.account}:instance/{instance.id}"
            )
            assert result[0].resource_tags is None
            assert result[0].region == AWS_REGION_US_EAST_1

    @mock_aws
    def test_one_ec2_with_verified_secret(self):
        from prowler.lib.check.models import Severity

        ec2 = resource("ec2", region_name=AWS_REGION_US_EAST_1)
        instance = ec2.create_instances(
            ImageId=EXAMPLE_AMI_ID,
            MinCount=1,
            MaxCount=1,
            UserData='STRIPE_KEY="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"',
        )[0]

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1],
            audit_config={"secrets_validate": True},
        )

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.ec2.ec2_instance_secrets_user_data.ec2_instance_secrets_user_data.ec2_client",
                new=EC2(aws_provider),
            ),
            mock.patch(
                "prowler.providers.aws.services.ec2.ec2_instance_secrets_user_data.ec2_instance_secrets_user_data.detect_secrets_scan_batch",
                return_value={
                    0: [
                        {
                            "type": "JSON Web Token (base64url-encoded)",
                            "line_number": 1,
                            "filename": "data",
                            "hashed_secret": "x",
                            "is_verified": True,
                        }
                    ]
                },
            ) as mock_scan,
        ):
            from prowler.providers.aws.services.ec2.ec2_instance_secrets_user_data.ec2_instance_secrets_user_data import (
                ec2_instance_secrets_user_data,
            )

            check = ec2_instance_secrets_user_data()
            result = check.execute()

            # The check must forward secrets_validate from the config to the scan.
            assert mock_scan.call_args.kwargs.get("validate") is True
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].check_metadata.Severity == Severity.critical
            assert "confirmed to be live" in result[0].status_extended
            assert result[0].resource_id == instance.id

    @mock_aws
    def test_one_secrets_with_unicode_error(self):
        invalid_utf8_bytes = b"\xc0\xaf"
        ec2 = resource("ec2", region_name=AWS_REGION_US_EAST_1)
        ec2.create_instances(
            ImageId=EXAMPLE_AMI_ID, MinCount=1, MaxCount=1, UserData=invalid_utf8_bytes
        )

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.ec2.ec2_instance_secrets_user_data.ec2_instance_secrets_user_data.ec2_client",
                new=EC2(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.ec2.ec2_instance_secrets_user_data.ec2_instance_secrets_user_data import (
                ec2_instance_secrets_user_data,
            )

            check = ec2_instance_secrets_user_data()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "MANUAL"
            assert "Could not decode User Data" in result[0].status_extended

    @mock_aws
    def test_scan_failure_reports_manual(self):
        from prowler.lib.utils.utils import SecretsScanError

        ec2 = resource("ec2", region_name=AWS_REGION_US_EAST_1)
        instance = ec2.create_instances(
            ImageId=EXAMPLE_AMI_ID,
            MinCount=1,
            MaxCount=1,
            UserData='password = "Tr0ub4dor3xKq9vLmZ"',
        )[0]

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.ec2.ec2_instance_secrets_user_data.ec2_instance_secrets_user_data.ec2_client",
                new=EC2(aws_provider),
            ),
            mock.patch(
                "prowler.providers.aws.services.ec2.ec2_instance_secrets_user_data.ec2_instance_secrets_user_data.detect_secrets_scan_batch",
                side_effect=SecretsScanError("Kingfisher exited with code 1"),
            ),
        ):
            from prowler.providers.aws.services.ec2.ec2_instance_secrets_user_data.ec2_instance_secrets_user_data import (
                ec2_instance_secrets_user_data,
            )

            check = ec2_instance_secrets_user_data()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "MANUAL"
            assert "Could not scan" in result[0].status_extended
            assert result[0].resource_id == instance.id
