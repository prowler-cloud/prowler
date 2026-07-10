import json
from unittest import mock

from boto3 import client, resource
from moto import mock_aws

from tests.providers.aws.utils import AWS_REGION_US_EAST_1, set_mocked_aws_provider

EXAMPLE_AMI_ID = "ami-12c6146b"

CHECK_MODULE = (
    "prowler.providers.aws.services.ec2.ec2_enclave_parent_iam_role_overprivileged"
    ".ec2_enclave_parent_iam_role_overprivileged"
)

ASSUME_ROLE_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"Service": "ec2.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }
    ],
}


def _create_role_with_inline_policy(role_name, policy_document):
    iam = client("iam")
    iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(ASSUME_ROLE_POLICY)
    )
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="workload-policy",
        PolicyDocument=json.dumps(policy_document),
    )
    profile = iam.create_instance_profile(InstanceProfileName=role_name)[
        "InstanceProfile"
    ]
    iam.add_role_to_instance_profile(InstanceProfileName=role_name, RoleName=role_name)
    return profile["Arn"]


def _create_enclave_instance(instance_profile_arn=None):
    ec2r = resource("ec2", region_name=AWS_REGION_US_EAST_1)
    kwargs = dict(ImageId=EXAMPLE_AMI_ID, MinCount=1, MaxCount=1)
    if instance_profile_arn:
        kwargs["IamInstanceProfile"] = {"Arn": instance_profile_arn}
    return ec2r.create_instances(**kwargs)[0]


class Test_ec2_enclave_parent_iam_role_overprivileged:
    @mock_aws
    def test_no_instances(self):
        from prowler.providers.aws.services.ec2.ec2_service import EC2
        from prowler.providers.aws.services.iam.iam_service import IAM

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(f"{CHECK_MODULE}.ec2_client", new=EC2(aws_provider)),
            mock.patch(f"{CHECK_MODULE}.iam_client", new=IAM(aws_provider)),
        ):
            from prowler.providers.aws.services.ec2.ec2_enclave_parent_iam_role_overprivileged.ec2_enclave_parent_iam_role_overprivileged import (
                ec2_enclave_parent_iam_role_overprivileged,
            )

            assert ec2_enclave_parent_iam_role_overprivileged().execute() == []

    @mock_aws
    def test_scoped_policy_pass(self):
        profile_arn = _create_role_with_inline_policy(
            "enclave-parent-role",
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "kms:Decrypt",
                        "Resource": "arn:aws:kms:us-east-1:123456789012:key/scoped",
                    }
                ],
            },
        )
        _create_enclave_instance(profile_arn)

        from prowler.providers.aws.services.ec2.ec2_service import EC2
        from prowler.providers.aws.services.iam.iam_service import IAM

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(f"{CHECK_MODULE}.ec2_client", new=EC2(aws_provider)) as ec2c,
            mock.patch(f"{CHECK_MODULE}.iam_client", new=IAM(aws_provider)),
        ):
            from prowler.providers.aws.services.ec2.ec2_enclave_parent_iam_role_overprivileged.ec2_enclave_parent_iam_role_overprivileged import (
                ec2_enclave_parent_iam_role_overprivileged,
            )

            ec2c.instances[0].enclaves_enabled = True
            result = ec2_enclave_parent_iam_role_overprivileged().execute()
            assert len(result) == 1
            assert result[0].status == "PASS"

    @mock_aws
    def test_kms_wildcard_fail(self):
        profile_arn = _create_role_with_inline_policy(
            "enclave-parent-role",
            {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Action": "kms:*", "Resource": "*"}
                ],
            },
        )
        _create_enclave_instance(profile_arn)

        from prowler.providers.aws.services.ec2.ec2_service import EC2
        from prowler.providers.aws.services.iam.iam_service import IAM

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(f"{CHECK_MODULE}.ec2_client", new=EC2(aws_provider)) as ec2c,
            mock.patch(f"{CHECK_MODULE}.iam_client", new=IAM(aws_provider)),
        ):
            from prowler.providers.aws.services.ec2.ec2_enclave_parent_iam_role_overprivileged.ec2_enclave_parent_iam_role_overprivileged import (
                ec2_enclave_parent_iam_role_overprivileged,
            )

            ec2c.instances[0].enclaves_enabled = True
            result = ec2_enclave_parent_iam_role_overprivileged().execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "kms:*" in result[0].status_extended

    @mock_aws
    def test_admin_wildcard_fail(self):
        profile_arn = _create_role_with_inline_policy(
            "enclave-parent-role",
            {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Action": "*", "Resource": "*"}
                ],
            },
        )
        _create_enclave_instance(profile_arn)

        from prowler.providers.aws.services.ec2.ec2_service import EC2
        from prowler.providers.aws.services.iam.iam_service import IAM

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(f"{CHECK_MODULE}.ec2_client", new=EC2(aws_provider)) as ec2c,
            mock.patch(f"{CHECK_MODULE}.iam_client", new=IAM(aws_provider)),
        ):
            from prowler.providers.aws.services.ec2.ec2_enclave_parent_iam_role_overprivileged.ec2_enclave_parent_iam_role_overprivileged import (
                ec2_enclave_parent_iam_role_overprivileged,
            )

            ec2c.instances[0].enclaves_enabled = True
            result = ec2_enclave_parent_iam_role_overprivileged().execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "'*'" in result[0].status_extended

    @mock_aws
    def test_no_instance_profile_pass(self):
        _create_enclave_instance()

        from prowler.providers.aws.services.ec2.ec2_service import EC2
        from prowler.providers.aws.services.iam.iam_service import IAM

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(f"{CHECK_MODULE}.ec2_client", new=EC2(aws_provider)) as ec2c,
            mock.patch(f"{CHECK_MODULE}.iam_client", new=IAM(aws_provider)),
        ):
            from prowler.providers.aws.services.ec2.ec2_enclave_parent_iam_role_overprivileged.ec2_enclave_parent_iam_role_overprivileged import (
                ec2_enclave_parent_iam_role_overprivileged,
            )

            ec2c.instances[0].enclaves_enabled = True
            result = ec2_enclave_parent_iam_role_overprivileged().execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "no instance profile" in result[0].status_extended

    @mock_aws
    def test_divergent_profile_and_role_names_still_detects_wildcard_fail(self):
        # Terraform / CloudFormation pattern: profile name != role name.
        # Old resolver matched by name and would PASS silently on this.
        iam = client("iam")
        role_name = "workload-role"
        profile_name = "compute-profile"
        iam.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(ASSUME_ROLE_POLICY),
        )
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName="workload-policy",
            PolicyDocument=json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {"Effect": "Allow", "Action": "kms:*", "Resource": "*"}
                    ],
                }
            ),
        )
        profile = iam.create_instance_profile(InstanceProfileName=profile_name)[
            "InstanceProfile"
        ]
        iam.add_role_to_instance_profile(
            InstanceProfileName=profile_name, RoleName=role_name
        )
        _create_enclave_instance(profile["Arn"])

        from prowler.providers.aws.services.ec2.ec2_service import EC2
        from prowler.providers.aws.services.iam.iam_service import IAM

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(f"{CHECK_MODULE}.ec2_client", new=EC2(aws_provider)) as ec2c,
            mock.patch(f"{CHECK_MODULE}.iam_client", new=IAM(aws_provider)),
        ):
            from prowler.providers.aws.services.ec2.ec2_enclave_parent_iam_role_overprivileged.ec2_enclave_parent_iam_role_overprivileged import (
                ec2_enclave_parent_iam_role_overprivileged,
            )

            ec2c.instances[0].enclaves_enabled = True
            result = ec2_enclave_parent_iam_role_overprivileged().execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "kms:*" in result[0].status_extended
            assert role_name in result[0].status_extended

    @mock_aws
    def test_unresolvable_profile_fails_closed(self):
        # Instance references a profile ARN that IAM doesn't know about
        # (e.g., deleted profile still referenced by an instance). The check
        # must FAIL closed instead of silent PASS. Moto rejects creating an
        # instance with a non-existent profile, so we mutate the field after
        # service construction — same pattern used for enclaves_enabled.
        _create_enclave_instance()

        from prowler.providers.aws.services.ec2.ec2_service import EC2
        from prowler.providers.aws.services.iam.iam_service import IAM

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(f"{CHECK_MODULE}.ec2_client", new=EC2(aws_provider)) as ec2c,
            mock.patch(f"{CHECK_MODULE}.iam_client", new=IAM(aws_provider)),
        ):
            from prowler.providers.aws.services.ec2.ec2_enclave_parent_iam_role_overprivileged.ec2_enclave_parent_iam_role_overprivileged import (
                ec2_enclave_parent_iam_role_overprivileged,
            )

            ec2c.instances[0].enclaves_enabled = True
            ec2c.instances[0].instance_profile = {
                "Arn": (
                    "arn:aws:iam::123456789012:instance-profile/ghost-profile"
                )
            }
            result = ec2_enclave_parent_iam_role_overprivileged().execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "could not be resolved" in result[0].status_extended
