from unittest import mock

from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import (
    AWS_REGION_EU_WEST_1,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)


class Test_s3_bucket_cross_region_replication:
    # No Buckets
    @mock_aws
    def test_no_buckets(self):
        from prowler.providers.aws.services.s3.s3_service import S3

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1]
        )

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.s3.s3_bucket_cross_region_replication.s3_bucket_cross_region_replication.s3_client",
                new=S3(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.s3.s3_bucket_cross_region_replication.s3_bucket_cross_region_replication import (
                    s3_bucket_cross_region_replication,
                )

                check = s3_bucket_cross_region_replication()
                result = check.execute()

                assert len(result) == 0

    @mock_aws
    def test_bucket_no_versioning(self):
        s3_client_us_east_1 = client("s3", region_name=AWS_REGION_US_EAST_1)
        bucket_name_us = "bucket_test_us"
        s3_client_us_east_1.create_bucket(Bucket=bucket_name_us)

        from prowler.providers.aws.services.s3.s3_service import S3

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1]
        )

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.s3.s3_bucket_cross_region_replication.s3_bucket_cross_region_replication.s3_client",
                new=S3(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.s3.s3_bucket_cross_region_replication.s3_bucket_cross_region_replication import (
                    s3_bucket_cross_region_replication,
                )

                check = s3_bucket_cross_region_replication()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == f"S3 Bucket {bucket_name_us} does not have correct cross region replication configuration."
                )
                assert result[0].resource_id == bucket_name_us
                assert (
                    result[0].resource_arn
                    == f"arn:{aws_provider.identity.partition}:s3:::{bucket_name_us}"
                )
                assert result[0].region == AWS_REGION_US_EAST_1

    @mock_aws
    def test_bucket_no_replication(self):
        s3_client_us_east_1 = client("s3", region_name=AWS_REGION_US_EAST_1)
        bucket_name_us = "bucket_test_us"
        s3_client_us_east_1.create_bucket(
            Bucket=bucket_name_us, ObjectOwnership="BucketOwnerEnforced"
        )
        s3_client_us_east_1.put_bucket_versioning(
            Bucket=bucket_name_us,
            VersioningConfiguration={"Status": "Enabled"},
        )

        from prowler.providers.aws.services.s3.s3_service import S3

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1]
        )

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.s3.s3_bucket_cross_region_replication.s3_bucket_cross_region_replication.s3_client",
                new=S3(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.s3.s3_bucket_cross_region_replication.s3_bucket_cross_region_replication import (
                    s3_bucket_cross_region_replication,
                )

                check = s3_bucket_cross_region_replication()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == f"S3 Bucket {bucket_name_us} does not have correct cross region replication configuration."
                )
                assert result[0].resource_id == bucket_name_us
                assert (
                    result[0].resource_arn
                    == f"arn:{aws_provider.identity.partition}:s3:::{bucket_name_us}"
                )
                assert result[0].region == AWS_REGION_US_EAST_1

    @mock_aws
    def test_bucket_versioning_enabled_replication_disabled(self):
        # EU-WEST-1 Destination Bucket
        s3_client_eu_west_1 = client("s3", region_name=AWS_REGION_EU_WEST_1)
        bucket_name_eu = "bucket_test_eu"
        s3_client_eu_west_1.create_bucket(
            Bucket=bucket_name_eu,
            ObjectOwnership="BucketOwnerEnforced",
            CreateBucketConfiguration={"LocationConstraint": AWS_REGION_EU_WEST_1},
        )
        s3_client_eu_west_1.put_bucket_versioning(
            Bucket=bucket_name_eu,
            VersioningConfiguration={"Status": "Enabled"},
        )
        # US-EAST-1 Source Bucket
        s3_client_us_east_1 = client("s3", region_name=AWS_REGION_US_EAST_1)
        bucket_name_us = "bucket_test_us"
        s3_client_us_east_1.create_bucket(
            Bucket=bucket_name_us, ObjectOwnership="BucketOwnerEnforced"
        )
        s3_client_us_east_1.put_bucket_versioning(
            Bucket=bucket_name_us,
            VersioningConfiguration={"Status": "Enabled"},
        )
        s3_client_us_east_1.put_bucket_replication(
            Bucket=bucket_name_us,
            ReplicationConfiguration={
                "Role": "arn:aws:iam",
                "Rules": [
                    {
                        "ID": "rule1",
                        "Status": "Disabled",
                        "Prefix": "",
                        "Destination": {
                            "Bucket": "arn:aws:s3:::bucket_test_eu",
                            "Account": "",
                        },
                    }
                ],
            },
        )

        from prowler.providers.aws.services.s3.s3_service import S3

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1]
        )

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.s3.s3_bucket_cross_region_replication.s3_bucket_cross_region_replication.s3_client",
                new=S3(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.s3.s3_bucket_cross_region_replication.s3_bucket_cross_region_replication import (
                    s3_bucket_cross_region_replication,
                )

                check = s3_bucket_cross_region_replication()
                result = check.execute()

                assert len(result) == 2

                # EU-WEST-1 Destination Bucket
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == f"S3 Bucket {bucket_name_eu} does not have correct cross region replication configuration."
                )
                assert result[0].resource_id == bucket_name_eu
                assert (
                    result[0].resource_arn
                    == f"arn:{aws_provider.identity.partition}:s3:::{bucket_name_eu}"
                )
                assert result[0].region == AWS_REGION_EU_WEST_1

                # US-EAST-1 Source Bucket
                assert result[1].status == "FAIL"
                assert (
                    result[1].status_extended
                    == f"S3 Bucket {bucket_name_us} does not have correct cross region replication configuration."
                )
                assert result[1].resource_id == bucket_name_us
                assert (
                    result[1].resource_arn
                    == f"arn:{aws_provider.identity.partition}:s3:::{bucket_name_us}"
                )
                assert result[1].region == AWS_REGION_US_EAST_1

    @mock_aws
    def test_bucket_versioning_enabled_replication_enabled(self):
        # EU-WEST-1 Destination Bucket
        s3_client_eu_west_1 = client("s3", region_name=AWS_REGION_EU_WEST_1)
        bucket_name_eu = "bucket_test_eu"
        arn_bucket_eu = f"arn:aws:s3:::{bucket_name_eu}"
        s3_client_eu_west_1.create_bucket(
            Bucket=bucket_name_eu,
            ObjectOwnership="BucketOwnerEnforced",
            CreateBucketConfiguration={"LocationConstraint": AWS_REGION_EU_WEST_1},
        )
        s3_client_eu_west_1.put_bucket_versioning(
            Bucket=bucket_name_eu,
            VersioningConfiguration={"Status": "Enabled"},
        )
        # US-EAST-1 Source Bucket
        s3_client_us_east_1 = client("s3", region_name=AWS_REGION_US_EAST_1)
        bucket_name_us = "bucket_test_us"
        s3_client_us_east_1.create_bucket(
            Bucket=bucket_name_us, ObjectOwnership="BucketOwnerEnforced"
        )
        s3_client_us_east_1.put_bucket_versioning(
            Bucket=bucket_name_us,
            VersioningConfiguration={"Status": "Enabled"},
        )
        repl_rule_id = "rule1"
        s3_client_us_east_1.put_bucket_replication(
            Bucket=bucket_name_us,
            ReplicationConfiguration={
                "Role": "arn:aws:iam",
                "Rules": [
                    {
                        "ID": repl_rule_id,
                        "Status": "Enabled",
                        "Prefix": "",
                        "Destination": {
                            "Bucket": arn_bucket_eu,
                            "Account": "",
                        },
                    }
                ],
            },
        )

        from prowler.providers.aws.services.s3.s3_service import S3

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1]
        )

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.s3.s3_bucket_cross_region_replication.s3_bucket_cross_region_replication.s3_client",
                new=S3(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.s3.s3_bucket_cross_region_replication.s3_bucket_cross_region_replication import (
                    s3_bucket_cross_region_replication,
                )

                check = s3_bucket_cross_region_replication()
                result = check.execute()

                assert len(result) == 2

                # EU-WEST-1 Destination Bucket
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == f"S3 Bucket {bucket_name_eu} does not have correct cross region replication configuration."
                )
                assert result[0].resource_id == bucket_name_eu
                assert (
                    result[0].resource_arn
                    == f"arn:{aws_provider.identity.partition}:s3:::{bucket_name_eu}"
                )
                assert result[0].region == AWS_REGION_EU_WEST_1

                # US-EAST-1 Source Bucket
                assert result[1].status == "PASS"
                assert (
                    result[1].status_extended
                    == f"S3 Bucket {bucket_name_us} has cross region replication rule {repl_rule_id} in bucket {bucket_name_eu} located in region {AWS_REGION_EU_WEST_1}."
                )
                assert result[1].resource_id == bucket_name_us
                assert (
                    result[1].resource_arn
                    == f"arn:{aws_provider.identity.partition}:s3:::{bucket_name_us}"
                )
                assert result[1].region == AWS_REGION_US_EAST_1

    @mock_aws
    def test_buckets_in_same_region(self):
        s3_client_us_east_1 = client("s3", region_name=AWS_REGION_US_EAST_1)
        # US-EAST-1 Destination Bucket
        bucket_name_destination = "bucket_test_destination"
        bucket_arn_destination = f"arn:aws:s3:::{bucket_name_destination}"
        s3_client_us_east_1.create_bucket(
            Bucket=bucket_name_destination, ObjectOwnership="BucketOwnerEnforced"
        )
        s3_client_us_east_1.put_bucket_versioning(
            Bucket=bucket_name_destination,
            VersioningConfiguration={"Status": "Enabled"},
        )
        # US-EAST-1 Source Bucket
        bucket_name_source = "bucket_test_source"
        s3_client_us_east_1.create_bucket(
            Bucket=bucket_name_source, ObjectOwnership="BucketOwnerEnforced"
        )
        s3_client_us_east_1.put_bucket_versioning(
            Bucket=bucket_name_source,
            VersioningConfiguration={"Status": "Enabled"},
        )
        repl_rule_id = "rule1"
        s3_client_us_east_1.put_bucket_replication(
            Bucket=bucket_name_source,
            ReplicationConfiguration={
                "Role": "arn:aws:iam",
                "Rules": [
                    {
                        "ID": repl_rule_id,
                        "Status": "Enabled",
                        "Prefix": "",
                        "Destination": {
                            "Bucket": bucket_arn_destination,
                            "Account": "",
                        },
                    }
                ],
            },
        )

        from prowler.providers.aws.services.s3.s3_service import S3

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.s3.s3_bucket_cross_region_replication.s3_bucket_cross_region_replication.s3_client",
                new=S3(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.s3.s3_bucket_cross_region_replication.s3_bucket_cross_region_replication import (
                    s3_bucket_cross_region_replication,
                )

                check = s3_bucket_cross_region_replication()
                result = check.execute()

                assert len(result) == 2

                # EU-WEST-1 Destination Bucket
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == f"S3 Bucket {bucket_name_destination} does not have correct cross region replication configuration."
                )
                assert result[0].resource_id == bucket_name_destination
                assert (
                    result[0].resource_arn
                    == f"arn:{aws_provider.identity.partition}:s3:::{bucket_name_destination}"
                )
                assert result[0].region == AWS_REGION_US_EAST_1

                # US-EAST-1 Source Bucket
                assert result[1].status == "FAIL"
                assert (
                    result[1].status_extended
                    == f"S3 Bucket {bucket_name_source} has cross region replication rule {repl_rule_id} in bucket {bucket_name_destination} located in the same region."
                )
                assert result[1].resource_id == bucket_name_source
                assert (
                    result[1].resource_arn
                    == f"arn:{aws_provider.identity.partition}:s3:::{bucket_name_source}"
                )
                assert result[1].region == AWS_REGION_US_EAST_1

    @mock_aws
    def test_source_bucket_several_replcation_rules(self):
        # EU-WEST-1 Destination Bucket
        s3_client_eu_west_1 = client("s3", region_name=AWS_REGION_EU_WEST_1)
        bucket_name_eu = "bucket_test_eu"
        arn_bucket_eu = f"arn:aws:s3:::{bucket_name_eu}"
        s3_client_eu_west_1.create_bucket(
            Bucket=bucket_name_eu,
            ObjectOwnership="BucketOwnerEnforced",
            CreateBucketConfiguration={"LocationConstraint": AWS_REGION_EU_WEST_1},
        )
        s3_client_eu_west_1.put_bucket_versioning(
            Bucket=bucket_name_eu,
            VersioningConfiguration={"Status": "Enabled"},
        )

        # US-EAST-1 Destination Bucket
        s3_client_us_east_1 = client("s3", region_name=AWS_REGION_US_EAST_1)
        bucket_name_us_destination = "bucket_test_us_destination"
        arn_bucket_us_destination = f"arn:aws:s3:::{bucket_name_us_destination}"
        s3_client_us_east_1.create_bucket(
            Bucket=bucket_name_us_destination, ObjectOwnership="BucketOwnerEnforced"
        )
        s3_client_us_east_1.put_bucket_versioning(
            Bucket=bucket_name_us_destination,
            VersioningConfiguration={"Status": "Enabled"},
        )

        # US-EAST-1 Source Bucket
        bucket_name_us_source = "bucket_test_us_source"
        s3_client_us_east_1.create_bucket(
            Bucket=bucket_name_us_source, ObjectOwnership="BucketOwnerEnforced"
        )
        s3_client_us_east_1.put_bucket_versioning(
            Bucket=bucket_name_us_source,
            VersioningConfiguration={"Status": "Enabled"},
        )
        repl_rule_id_1 = "rule1"
        repl_rule_id_2 = "rule2"
        s3_client_us_east_1.put_bucket_replication(
            Bucket=bucket_name_us_source,
            ReplicationConfiguration={
                "Role": "arn:aws:iam",
                "Rules": [
                    {
                        "ID": repl_rule_id_1,
                        "Status": "Enabled",
                        "Prefix": "",
                        "Destination": {
                            "Bucket": arn_bucket_eu,
                            "Account": "",
                        },
                    },
                    {
                        "ID": repl_rule_id_2,
                        "Status": "Enabled",
                        "Prefix": "",
                        "Destination": {
                            "Bucket": arn_bucket_us_destination,
                            "Account": "",
                        },
                    },
                ],
            },
        )

        from prowler.providers.aws.services.s3.s3_service import S3

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1]
        )

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.s3.s3_bucket_cross_region_replication.s3_bucket_cross_region_replication.s3_client",
                new=S3(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.s3.s3_bucket_cross_region_replication.s3_bucket_cross_region_replication import (
                    s3_bucket_cross_region_replication,
                )

                check = s3_bucket_cross_region_replication()
                result = check.execute()

                assert len(result) == 3

                # EU-WEST-1 Destination Bucket
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == f"S3 Bucket {bucket_name_eu} does not have correct cross region replication configuration."
                )
                assert result[0].resource_id == bucket_name_eu
                assert (
                    result[0].resource_arn
                    == f"arn:{aws_provider.identity.partition}:s3:::{bucket_name_eu}"
                )
                assert result[0].region == AWS_REGION_EU_WEST_1

                # US-EAST-1 Destination Bucket
                assert result[1].status == "FAIL"
                assert (
                    result[1].status_extended
                    == f"S3 Bucket {bucket_name_us_destination} does not have correct cross region replication configuration."
                )
                assert result[1].resource_id == bucket_name_us_destination
                assert (
                    result[1].resource_arn
                    == f"arn:{aws_provider.identity.partition}:s3:::{bucket_name_us_destination}"
                )
                assert result[1].region == AWS_REGION_US_EAST_1

                # US-EAST-1 Source Bucket
                assert result[2].status == "PASS"
                assert (
                    result[2].status_extended
                    == f"S3 Bucket {bucket_name_us_source} has cross region replication rule {repl_rule_id_1} in bucket {bucket_name_eu} located in region {AWS_REGION_EU_WEST_1}."
                )
                assert result[2].resource_id == bucket_name_us_source
                assert (
                    result[2].resource_arn
                    == f"arn:{aws_provider.identity.partition}:s3:::{bucket_name_us_source}"
                )
                assert result[2].region == AWS_REGION_US_EAST_1

    @mock_aws
    def test_destination_bucket_out_of_scope(self):
        # EU-WEST-1 Destination Bucket
        s3_client_eu_west_1 = client("s3", region_name=AWS_REGION_EU_WEST_1)
        bucket_name_eu = "bucket_test_eu"
        arn_bucket_eu = f"arn:aws:s3:::{bucket_name_eu}"
        s3_client_eu_west_1.create_bucket(
            Bucket=bucket_name_eu,
            ObjectOwnership="BucketOwnerEnforced",
            CreateBucketConfiguration={"LocationConstraint": AWS_REGION_EU_WEST_1},
        )
        s3_client_eu_west_1.put_bucket_versioning(
            Bucket=bucket_name_eu,
            VersioningConfiguration={"Status": "Enabled"},
        )

        # US-EAST-1 Source Bucket
        s3_client_us_east_1 = client("s3", region_name=AWS_REGION_US_EAST_1)
        bucket_name_us = "bucket_test_us_source"
        s3_client_us_east_1.create_bucket(
            Bucket=bucket_name_us, ObjectOwnership="BucketOwnerEnforced"
        )
        s3_client_us_east_1.put_bucket_versioning(
            Bucket=bucket_name_us,
            VersioningConfiguration={"Status": "Enabled"},
        )
        repl_rule_id = "rule1"
        s3_client_us_east_1.put_bucket_replication(
            Bucket=bucket_name_us,
            ReplicationConfiguration={
                "Role": "arn:aws:iam",
                "Rules": [
                    {
                        "ID": repl_rule_id,
                        "Status": "Enabled",
                        "Prefix": "",
                        "Destination": {
                            "Bucket": arn_bucket_eu,
                            "Account": "",
                        },
                    },
                ],
            },
        )

        from prowler.providers.aws.services.s3.s3_service import S3

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.s3.s3_bucket_cross_region_replication.s3_bucket_cross_region_replication.s3_client",
                new=S3(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.s3.s3_bucket_cross_region_replication.s3_bucket_cross_region_replication import (
                    s3_bucket_cross_region_replication,
                )

                check = s3_bucket_cross_region_replication()
                result = check.execute()

                assert len(result) == 1

                # US-EAST-1 Source Bucket
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == f"S3 Bucket {bucket_name_us} has cross region replication rule {repl_rule_id} in bucket {arn_bucket_eu.split(':')[-1]} which is out of Prowler's scope."
                )
                assert result[0].resource_id == bucket_name_us
                assert (
                    result[0].resource_arn
                    == f"arn:{aws_provider.identity.partition}:s3:::{bucket_name_us}"
                )
                assert result[0].region == AWS_REGION_US_EAST_1
