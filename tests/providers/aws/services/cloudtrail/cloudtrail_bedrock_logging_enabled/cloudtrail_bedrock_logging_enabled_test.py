from unittest import mock

from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

CHECK_MODULE_PATH = "prowler.providers.aws.services.cloudtrail.cloudtrail_bedrock_logging_enabled.cloudtrail_bedrock_logging_enabled"


class Test_cloudtrail_bedrock_logging_enabled:
    @mock_aws
    def test_no_trails(self):
        """Test when there are no CloudTrail trails configured."""
        from prowler.providers.aws.services.cloudtrail.cloudtrail_service import (
            Cloudtrail,
        )

        aws_provider = set_mocked_aws_provider()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                f"{CHECK_MODULE_PATH}.cloudtrail_client",
                new=Cloudtrail(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.cloudtrail.cloudtrail_bedrock_logging_enabled.cloudtrail_bedrock_logging_enabled import (
                cloudtrail_bedrock_logging_enabled,
            )

            check = cloudtrail_bedrock_logging_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "No CloudTrail trails are configured to log Amazon Bedrock API calls."
            )
            assert result[0].resource_id == AWS_ACCOUNT_NUMBER
            assert (
                result[0].resource_arn
                == f"arn:aws:cloudtrail:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:trail"
            )
            assert result[0].region == AWS_REGION_US_EAST_1

    @mock_aws
    def test_trail_not_logging(self):
        """Test when a trail exists but is not actively logging."""
        cloudtrail_client_us = client("cloudtrail", region_name=AWS_REGION_US_EAST_1)
        s3_client_us = client("s3", region_name=AWS_REGION_US_EAST_1)
        trail_name = "trail_test"
        bucket_name = "bucket_test"
        s3_client_us.create_bucket(Bucket=bucket_name)
        cloudtrail_client_us.create_trail(
            Name=trail_name, S3BucketName=bucket_name, IsMultiRegionTrail=False
        )
        cloudtrail_client_us.put_event_selectors(
            TrailName=trail_name,
            EventSelectors=[
                {
                    "ReadWriteType": "All",
                    "IncludeManagementEvents": True,
                    "DataResources": [
                        {"Type": "AWS::S3::Object", "Values": ["arn:aws:s3"]}
                    ],
                }
            ],
        )
        # Trail is not started, so is_logging remains False

        from prowler.providers.aws.services.cloudtrail.cloudtrail_service import (
            Cloudtrail,
        )

        aws_provider = set_mocked_aws_provider()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                f"{CHECK_MODULE_PATH}.cloudtrail_client",
                new=Cloudtrail(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.cloudtrail.cloudtrail_bedrock_logging_enabled.cloudtrail_bedrock_logging_enabled import (
                cloudtrail_bedrock_logging_enabled,
            )

            check = cloudtrail_bedrock_logging_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "No CloudTrail trails are configured to log Amazon Bedrock API calls."
            )

    @mock_aws
    def test_trail_without_management_events(self):
        """Test when a trail has data events but no management events enabled."""
        cloudtrail_client_us = client("cloudtrail", region_name=AWS_REGION_US_EAST_1)
        s3_client_us = client("s3", region_name=AWS_REGION_US_EAST_1)
        trail_name = "trail_test"
        bucket_name = "bucket_test"
        s3_client_us.create_bucket(Bucket=bucket_name)
        cloudtrail_client_us.create_trail(
            Name=trail_name, S3BucketName=bucket_name, IsMultiRegionTrail=False
        )
        cloudtrail_client_us.start_logging(Name=trail_name)
        cloudtrail_client_us.put_event_selectors(
            TrailName=trail_name,
            EventSelectors=[
                {
                    "ReadWriteType": "All",
                    "IncludeManagementEvents": False,
                    "DataResources": [
                        {"Type": "AWS::S3::Object", "Values": ["arn:aws:s3"]}
                    ],
                }
            ],
        )

        from prowler.providers.aws.services.cloudtrail.cloudtrail_service import (
            Cloudtrail,
        )

        aws_provider = set_mocked_aws_provider()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                f"{CHECK_MODULE_PATH}.cloudtrail_client",
                new=Cloudtrail(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.cloudtrail.cloudtrail_bedrock_logging_enabled.cloudtrail_bedrock_logging_enabled import (
                cloudtrail_bedrock_logging_enabled,
            )

            check = cloudtrail_bedrock_logging_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "No CloudTrail trails are configured to log Amazon Bedrock API calls."
            )

    @mock_aws
    def test_trail_with_classic_management_events(self):
        """Test PASS when a trail has classic management events enabled."""
        cloudtrail_client_us = client("cloudtrail", region_name=AWS_REGION_US_EAST_1)
        s3_client_us = client("s3", region_name=AWS_REGION_US_EAST_1)
        trail_name = "trail_test"
        bucket_name = "bucket_test"
        s3_client_us.create_bucket(Bucket=bucket_name)
        trail = cloudtrail_client_us.create_trail(
            Name=trail_name, S3BucketName=bucket_name, IsMultiRegionTrail=False
        )
        cloudtrail_client_us.start_logging(Name=trail_name)
        cloudtrail_client_us.put_event_selectors(
            TrailName=trail_name,
            EventSelectors=[
                {
                    "ReadWriteType": "All",
                    "IncludeManagementEvents": True,
                    "DataResources": [
                        {"Type": "AWS::S3::Object", "Values": ["arn:aws:s3"]}
                    ],
                }
            ],
        )

        from prowler.providers.aws.services.cloudtrail.cloudtrail_service import (
            Cloudtrail,
        )

        aws_provider = set_mocked_aws_provider()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                f"{CHECK_MODULE_PATH}.cloudtrail_client",
                new=Cloudtrail(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.cloudtrail.cloudtrail_bedrock_logging_enabled.cloudtrail_bedrock_logging_enabled import (
                cloudtrail_bedrock_logging_enabled,
            )

            check = cloudtrail_bedrock_logging_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Trail {trail_name} from home region {AWS_REGION_US_EAST_1} has management events enabled to log Amazon Bedrock API calls."
            )
            assert result[0].resource_id == trail_name
            assert result[0].resource_arn == trail["TrailARN"]
            assert result[0].region == AWS_REGION_US_EAST_1

    @mock_aws
    def test_trail_with_classic_management_events_read_only(self):
        """Test FAIL when a trail has management events but ReadWriteType is ReadOnly."""
        cloudtrail_client_us = client("cloudtrail", region_name=AWS_REGION_US_EAST_1)
        s3_client_us = client("s3", region_name=AWS_REGION_US_EAST_1)
        trail_name = "trail_test"
        bucket_name = "bucket_test"
        s3_client_us.create_bucket(Bucket=bucket_name)
        cloudtrail_client_us.create_trail(
            Name=trail_name, S3BucketName=bucket_name, IsMultiRegionTrail=False
        )
        cloudtrail_client_us.start_logging(Name=trail_name)
        cloudtrail_client_us.put_event_selectors(
            TrailName=trail_name,
            EventSelectors=[
                {
                    "ReadWriteType": "ReadOnly",
                    "IncludeManagementEvents": True,
                    "DataResources": [
                        {"Type": "AWS::S3::Object", "Values": ["arn:aws:s3"]}
                    ],
                }
            ],
        )

        from prowler.providers.aws.services.cloudtrail.cloudtrail_service import (
            Cloudtrail,
        )

        aws_provider = set_mocked_aws_provider()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                f"{CHECK_MODULE_PATH}.cloudtrail_client",
                new=Cloudtrail(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.cloudtrail.cloudtrail_bedrock_logging_enabled.cloudtrail_bedrock_logging_enabled import (
                cloudtrail_bedrock_logging_enabled,
            )

            check = cloudtrail_bedrock_logging_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "No CloudTrail trails are configured to log Amazon Bedrock API calls."
            )

    @mock_aws
    def test_trail_with_advanced_management_events(self):
        """Test PASS when a trail has advanced management event selectors."""
        cloudtrail_client_us = client("cloudtrail", region_name=AWS_REGION_US_EAST_1)
        s3_client_us = client("s3", region_name=AWS_REGION_US_EAST_1)
        trail_name = "trail_test"
        bucket_name = "bucket_test"
        s3_client_us.create_bucket(Bucket=bucket_name)
        trail = cloudtrail_client_us.create_trail(
            Name=trail_name, S3BucketName=bucket_name, IsMultiRegionTrail=False
        )
        cloudtrail_client_us.start_logging(Name=trail_name)
        cloudtrail_client_us.put_event_selectors(
            TrailName=trail_name,
            AdvancedEventSelectors=[
                {
                    "Name": "Management events selector",
                    "FieldSelectors": [
                        {"Field": "eventCategory", "Equals": ["Management"]},
                    ],
                },
            ],
        )

        from prowler.providers.aws.services.cloudtrail.cloudtrail_service import (
            Cloudtrail,
        )

        aws_provider = set_mocked_aws_provider()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                f"{CHECK_MODULE_PATH}.cloudtrail_client",
                new=Cloudtrail(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.cloudtrail.cloudtrail_bedrock_logging_enabled.cloudtrail_bedrock_logging_enabled import (
                cloudtrail_bedrock_logging_enabled,
            )

            check = cloudtrail_bedrock_logging_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Trail {trail_name} from home region {AWS_REGION_US_EAST_1} has an advanced event selector to log Amazon Bedrock API calls."
            )
            assert result[0].resource_id == trail_name
            assert result[0].resource_arn == trail["TrailARN"]
            assert result[0].region == AWS_REGION_US_EAST_1

    @mock_aws
    def test_trail_with_advanced_bedrock_data_events(self):
        """Test PASS when a trail has advanced event selectors for Bedrock resources."""
        from prowler.providers.aws.services.cloudtrail.cloudtrail_service import (
            Cloudtrail,
            Event_Selector,
        )

        cloudtrail_client_us = client("cloudtrail", region_name=AWS_REGION_US_EAST_1)
        s3_client_us = client("s3", region_name=AWS_REGION_US_EAST_1)
        trail_name = "trail_test"
        bucket_name = "bucket_test"
        s3_client_us.create_bucket(Bucket=bucket_name)
        trail = cloudtrail_client_us.create_trail(
            Name=trail_name, S3BucketName=bucket_name, IsMultiRegionTrail=False
        )
        cloudtrail_client_us.start_logging(Name=trail_name)

        aws_provider = set_mocked_aws_provider()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                f"{CHECK_MODULE_PATH}.cloudtrail_client",
                new=Cloudtrail(aws_provider),
            ) as mock_cloudtrail_client,
        ):
            # Manually inject the Bedrock advanced event selector since moto
            # does not support Bedrock resource types.
            trail_arn = trail["TrailARN"]
            mock_cloudtrail_client.trails[trail_arn].data_events = [
                Event_Selector(
                    is_advanced=True,
                    event_selector={
                        "Name": "Bedrock data events",
                        "FieldSelectors": [
                            {"Field": "eventCategory", "Equals": ["Data"]},
                            {
                                "Field": "resources.type",
                                "Equals": ["AWS::Bedrock::Model"],
                            },
                        ],
                    },
                )
            ]

            from prowler.providers.aws.services.cloudtrail.cloudtrail_bedrock_logging_enabled.cloudtrail_bedrock_logging_enabled import (
                cloudtrail_bedrock_logging_enabled,
            )

            check = cloudtrail_bedrock_logging_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Trail {trail_name} from home region {AWS_REGION_US_EAST_1} has an advanced event selector to log Amazon Bedrock API calls."
            )
            assert result[0].resource_id == trail_name
            assert result[0].resource_arn == trail["TrailARN"]
            assert result[0].region == AWS_REGION_US_EAST_1

    @mock_aws
    def test_trail_with_advanced_bedrock_guardrail_events(self):
        """Test PASS when a trail has advanced event selectors for Bedrock Guardrail resources."""
        from prowler.providers.aws.services.cloudtrail.cloudtrail_service import (
            Cloudtrail,
            Event_Selector,
        )

        cloudtrail_client_us = client("cloudtrail", region_name=AWS_REGION_US_EAST_1)
        s3_client_us = client("s3", region_name=AWS_REGION_US_EAST_1)
        trail_name = "trail_test"
        bucket_name = "bucket_test"
        s3_client_us.create_bucket(Bucket=bucket_name)
        trail = cloudtrail_client_us.create_trail(
            Name=trail_name, S3BucketName=bucket_name, IsMultiRegionTrail=False
        )
        cloudtrail_client_us.start_logging(Name=trail_name)

        aws_provider = set_mocked_aws_provider()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                f"{CHECK_MODULE_PATH}.cloudtrail_client",
                new=Cloudtrail(aws_provider),
            ) as mock_cloudtrail_client,
        ):
            # Manually inject the Bedrock Guardrail advanced event selector
            # since moto does not support Bedrock resource types.
            trail_arn = trail["TrailARN"]
            mock_cloudtrail_client.trails[trail_arn].data_events = [
                Event_Selector(
                    is_advanced=True,
                    event_selector={
                        "Name": "Bedrock guardrail events",
                        "FieldSelectors": [
                            {"Field": "eventCategory", "Equals": ["Data"]},
                            {
                                "Field": "resources.type",
                                "Equals": ["AWS::Bedrock::Guardrail"],
                            },
                        ],
                    },
                )
            ]

            from prowler.providers.aws.services.cloudtrail.cloudtrail_bedrock_logging_enabled.cloudtrail_bedrock_logging_enabled import (
                cloudtrail_bedrock_logging_enabled,
            )

            check = cloudtrail_bedrock_logging_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Trail {trail_name} from home region {AWS_REGION_US_EAST_1} has an advanced event selector to log Amazon Bedrock API calls."
            )
            assert result[0].resource_id == trail_name
            assert result[0].resource_arn == trail["TrailARN"]
            assert result[0].region == AWS_REGION_US_EAST_1

    @mock_aws
    def test_trail_with_advanced_non_bedrock_data_events(self):
        """Test FAIL when a trail has advanced event selectors for non-Bedrock resources."""
        cloudtrail_client_us = client("cloudtrail", region_name=AWS_REGION_US_EAST_1)
        s3_client_us = client("s3", region_name=AWS_REGION_US_EAST_1)
        trail_name = "trail_test"
        bucket_name = "bucket_test"
        s3_client_us.create_bucket(Bucket=bucket_name)
        cloudtrail_client_us.create_trail(
            Name=trail_name, S3BucketName=bucket_name, IsMultiRegionTrail=False
        )
        cloudtrail_client_us.start_logging(Name=trail_name)
        cloudtrail_client_us.put_event_selectors(
            TrailName=trail_name,
            AdvancedEventSelectors=[
                {
                    "Name": "S3 data events",
                    "FieldSelectors": [
                        {"Field": "eventCategory", "Equals": ["Data"]},
                        {
                            "Field": "resources.type",
                            "Equals": ["AWS::S3::Object"],
                        },
                    ],
                },
            ],
        )

        from prowler.providers.aws.services.cloudtrail.cloudtrail_service import (
            Cloudtrail,
        )

        aws_provider = set_mocked_aws_provider()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                f"{CHECK_MODULE_PATH}.cloudtrail_client",
                new=Cloudtrail(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.cloudtrail.cloudtrail_bedrock_logging_enabled.cloudtrail_bedrock_logging_enabled import (
                cloudtrail_bedrock_logging_enabled,
            )

            check = cloudtrail_bedrock_logging_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "No CloudTrail trails are configured to log Amazon Bedrock API calls."
            )

    @mock_aws
    def test_trail_with_classic_management_events_write_only(self):
        """Test PASS when a trail has management events with ReadWriteType WriteOnly."""
        cloudtrail_client_us = client("cloudtrail", region_name=AWS_REGION_US_EAST_1)
        s3_client_us = client("s3", region_name=AWS_REGION_US_EAST_1)
        trail_name = "trail_test"
        bucket_name = "bucket_test"
        s3_client_us.create_bucket(Bucket=bucket_name)
        trail = cloudtrail_client_us.create_trail(
            Name=trail_name, S3BucketName=bucket_name, IsMultiRegionTrail=False
        )
        cloudtrail_client_us.start_logging(Name=trail_name)
        cloudtrail_client_us.put_event_selectors(
            TrailName=trail_name,
            EventSelectors=[
                {
                    "ReadWriteType": "WriteOnly",
                    "IncludeManagementEvents": True,
                    "DataResources": [],
                }
            ],
        )

        from prowler.providers.aws.services.cloudtrail.cloudtrail_service import (
            Cloudtrail,
        )

        aws_provider = set_mocked_aws_provider()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                f"{CHECK_MODULE_PATH}.cloudtrail_client",
                new=Cloudtrail(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.cloudtrail.cloudtrail_bedrock_logging_enabled.cloudtrail_bedrock_logging_enabled import (
                cloudtrail_bedrock_logging_enabled,
            )

            check = cloudtrail_bedrock_logging_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Trail {trail_name} from home region {AWS_REGION_US_EAST_1} has management events enabled to log Amazon Bedrock API calls."
            )
            assert result[0].resource_id == trail_name
            assert result[0].resource_arn == trail["TrailARN"]
            assert result[0].region == AWS_REGION_US_EAST_1

    @mock_aws
    def test_trail_with_advanced_management_events_read_only(self):
        """Test FAIL when advanced management event selector has readOnly=true restriction."""
        from prowler.providers.aws.services.cloudtrail.cloudtrail_service import (
            Cloudtrail,
            Event_Selector,
        )

        cloudtrail_client_us = client("cloudtrail", region_name=AWS_REGION_US_EAST_1)
        s3_client_us = client("s3", region_name=AWS_REGION_US_EAST_1)
        trail_name = "trail_test"
        bucket_name = "bucket_test"
        s3_client_us.create_bucket(Bucket=bucket_name)
        trail = cloudtrail_client_us.create_trail(
            Name=trail_name, S3BucketName=bucket_name, IsMultiRegionTrail=False
        )
        cloudtrail_client_us.start_logging(Name=trail_name)

        aws_provider = set_mocked_aws_provider()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                f"{CHECK_MODULE_PATH}.cloudtrail_client",
                new=Cloudtrail(aws_provider),
            ) as mock_cloudtrail_client,
        ):
            trail_arn = trail["TrailARN"]
            mock_cloudtrail_client.trails[trail_arn].data_events = [
                Event_Selector(
                    is_advanced=True,
                    event_selector={
                        "Name": "Management events selector",
                        "FieldSelectors": [
                            {"Field": "eventCategory", "Equals": ["Management"]},
                            {"Field": "readOnly", "Equals": ["true"]},
                        ],
                    },
                )
            ]

            from prowler.providers.aws.services.cloudtrail.cloudtrail_bedrock_logging_enabled.cloudtrail_bedrock_logging_enabled import (
                cloudtrail_bedrock_logging_enabled,
            )

            check = cloudtrail_bedrock_logging_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "No CloudTrail trails are configured to log Amazon Bedrock API calls."
            )

    @mock_aws
    def test_trail_with_advanced_management_events_other_service_event_source(self):
        """Test FAIL when advanced management events are scoped to a non-Bedrock event source."""
        from prowler.providers.aws.services.cloudtrail.cloudtrail_service import (
            Cloudtrail,
            Event_Selector,
        )

        cloudtrail_client_us = client("cloudtrail", region_name=AWS_REGION_US_EAST_1)
        s3_client_us = client("s3", region_name=AWS_REGION_US_EAST_1)
        trail_name = "trail_test"
        bucket_name = "bucket_test"
        s3_client_us.create_bucket(Bucket=bucket_name)
        trail = cloudtrail_client_us.create_trail(
            Name=trail_name, S3BucketName=bucket_name, IsMultiRegionTrail=False
        )
        cloudtrail_client_us.start_logging(Name=trail_name)

        aws_provider = set_mocked_aws_provider()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                f"{CHECK_MODULE_PATH}.cloudtrail_client",
                new=Cloudtrail(aws_provider),
            ) as mock_cloudtrail_client,
        ):
            trail_arn = trail["TrailARN"]
            mock_cloudtrail_client.trails[trail_arn].data_events = [
                Event_Selector(
                    is_advanced=True,
                    event_selector={
                        "Name": "EC2 management events selector",
                        "FieldSelectors": [
                            {"Field": "eventCategory", "Equals": ["Management"]},
                            {
                                "Field": "eventSource",
                                "Equals": ["ec2.amazonaws.com"],
                            },
                        ],
                    },
                )
            ]

            from prowler.providers.aws.services.cloudtrail.cloudtrail_bedrock_logging_enabled.cloudtrail_bedrock_logging_enabled import (
                cloudtrail_bedrock_logging_enabled,
            )

            check = cloudtrail_bedrock_logging_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "No CloudTrail trails are configured to log Amazon Bedrock API calls."
            )

    @mock_aws
    def test_access_denied(self):
        """Test when trails are None due to access denied."""
        from prowler.providers.aws.services.cloudtrail.cloudtrail_service import (
            Cloudtrail,
        )

        aws_provider = set_mocked_aws_provider()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                f"{CHECK_MODULE_PATH}.cloudtrail_client",
                new=Cloudtrail(aws_provider),
            ) as mock_cloudtrail_client,
        ):
            from prowler.providers.aws.services.cloudtrail.cloudtrail_bedrock_logging_enabled.cloudtrail_bedrock_logging_enabled import (
                cloudtrail_bedrock_logging_enabled,
            )

            mock_cloudtrail_client.trails = None
            check = cloudtrail_bedrock_logging_enabled()
            result = check.execute()

            assert len(result) == 0
