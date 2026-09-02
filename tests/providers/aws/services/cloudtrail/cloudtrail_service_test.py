import json
from unittest import mock

from boto3 import client
from moto import mock_aws

from prowler.providers.aws.services.cloudtrail.cloudtrail_service import (
    Cloudtrail,
    get_cloudtrail_threat_detection_identities,
    normalize_cloudtrail_identity,
)
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_SOUTH_2,
    AWS_REGION_EU_WEST_1,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)


class Test_Cloudtrail_Service:
    # Test Cloudtrail Service
    @mock_aws
    def test_service(self):
        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1]
        )
        cloudtrail = Cloudtrail(aws_provider)
        assert cloudtrail.service == "cloudtrail"

    # Test Cloudtrail client
    @mock_aws
    def test_client(self):
        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1]
        )
        cloudtrail = Cloudtrail(aws_provider)
        for regional_client in cloudtrail.regional_clients.values():
            assert regional_client.__class__.__name__ == "CloudTrail"

    # Test Cloudtrail session
    @mock_aws
    def test__get_session__(self):
        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1]
        )
        cloudtrail = Cloudtrail(aws_provider)
        assert cloudtrail.session.__class__.__name__ == "Session"

    # Test Cloudtrail Session
    @mock_aws
    def test_audited_account(self):
        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1]
        )
        cloudtrail = Cloudtrail(aws_provider)
        assert cloudtrail.audited_account == AWS_ACCOUNT_NUMBER

    @mock_aws
    def test_describe_trails(self):
        # USA
        cloudtrail_client_us_east_1 = client(
            "cloudtrail", region_name=AWS_REGION_US_EAST_1
        )
        s3_client_us_east_1 = client("s3", region_name=AWS_REGION_US_EAST_1)
        trail_name_us = "trail_test_us"
        bucket_name_us = "bucket_test_us"
        s3_client_us_east_1.create_bucket(Bucket=bucket_name_us)
        cloudtrail_client_us_east_1.create_trail(
            Name=trail_name_us,
            S3BucketName=bucket_name_us,
            IsMultiRegionTrail=False,
            TagsList=[
                {"Key": "test", "Value": "test"},
            ],
        )

        # IRELAND
        cloudtrail_client_eu_west_1 = client(
            "cloudtrail", region_name=AWS_REGION_EU_WEST_1
        )
        s3_client_eu_west_1 = client("s3", region_name=AWS_REGION_EU_WEST_1)
        trail_name_eu = "trail_test_eu"
        bucket_name_eu = "bucket_test_eu"
        s3_client_eu_west_1.create_bucket(
            Bucket=bucket_name_eu,
            CreateBucketConfiguration={"LocationConstraint": AWS_REGION_EU_WEST_1},
        )
        cloudtrail_client_eu_west_1.create_trail(
            Name=trail_name_eu,
            S3BucketName=bucket_name_eu,
            IsMultiRegionTrail=False,
            TagsList=[
                {"Key": "test", "Value": "test"},
            ],
        )
        # SPAIN
        cloudtrail_client_eu_south_2 = client(
            "cloudtrail", region_name=AWS_REGION_EU_SOUTH_2
        )
        s3_client_eu_south_2 = client("s3", region_name=AWS_REGION_EU_SOUTH_2)
        trail_name_sp = "trail_test_sp"
        bucket_name_sp = "bucket_test_sp"
        s3_client_eu_south_2.create_bucket(
            Bucket=bucket_name_sp,
            CreateBucketConfiguration={"LocationConstraint": AWS_REGION_EU_SOUTH_2},
        )
        cloudtrail_client_eu_south_2.create_trail(
            Name=trail_name_sp,
            S3BucketName=bucket_name_sp,
            IsMultiRegionTrail=True,
            TagsList=[
                {"Key": "test", "Value": "test"},
            ],
        )

        # We are not going to include AWS_REGION_EU_SOUTH_2 in the audited
        # regions, but that trail is regional so it'll appear
        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1]
        )
        cloudtrail = Cloudtrail(aws_provider)
        assert len(cloudtrail.trails) == 3
        for trail in cloudtrail.trails.values():
            if trail.name == trail_name_us:
                assert not trail.is_multiregion
                assert trail.home_region == AWS_REGION_US_EAST_1
                assert trail.region == AWS_REGION_US_EAST_1
                assert not trail.is_logging
                assert not trail.log_file_validation_enabled
                assert not trail.latest_cloudwatch_delivery_time
                assert trail.s3_bucket == bucket_name_us
                assert trail.tags == [
                    {"Key": "test", "Value": "test"},
                ]
            if trail.name == trail_name_eu:
                assert not trail.is_multiregion
                assert trail.home_region == AWS_REGION_EU_WEST_1
                assert trail.region == AWS_REGION_EU_WEST_1
                assert not trail.is_logging
                assert not trail.log_file_validation_enabled
                assert not trail.latest_cloudwatch_delivery_time
                assert trail.s3_bucket == bucket_name_eu
                assert trail.tags == [
                    {"Key": "test", "Value": "test"},
                ]
            if trail.name == trail_name_sp:
                assert trail.is_multiregion
                assert trail.home_region == AWS_REGION_EU_SOUTH_2
                # The region is the first audited region since the trail home region is not audited
                assert (
                    trail.region == AWS_REGION_US_EAST_1
                    or trail.region == AWS_REGION_EU_WEST_1
                )
                assert not trail.is_logging
                assert not trail.log_file_validation_enabled
                assert not trail.latest_cloudwatch_delivery_time
                assert trail.s3_bucket == bucket_name_sp
                # No tags since the trail region is not audited and the tags are retrieved from the regional endpoint
                assert trail.tags == []

    @mock_aws
    def test_status_trails(self):
        cloudtrail_client_us_east_1 = client(
            "cloudtrail", region_name=AWS_REGION_US_EAST_1
        )
        s3_client_us_east_1 = client("s3", region_name=AWS_REGION_US_EAST_1)
        cloudtrail_client_eu_west_1 = client(
            "cloudtrail", region_name=AWS_REGION_EU_WEST_1
        )
        s3_client_eu_west_1 = client("s3", region_name=AWS_REGION_EU_WEST_1)
        trail_name_us = "trail_test_us"
        bucket_name_us = "bucket_test_us"
        trail_name_eu = "trail_test_eu"
        bucket_name_eu = "bucket_test_eu"
        s3_client_us_east_1.create_bucket(Bucket=bucket_name_us)
        s3_client_eu_west_1.create_bucket(
            Bucket=bucket_name_eu,
            CreateBucketConfiguration={"LocationConstraint": AWS_REGION_EU_WEST_1},
        )
        cloudtrail_client_us_east_1.create_trail(
            Name=trail_name_us,
            S3BucketName=bucket_name_us,
            IsMultiRegionTrail=False,
            EnableLogFileValidation=True,
        )
        cloudtrail_client_us_east_1.start_logging(Name=trail_name_us)
        cloudtrail_client_eu_west_1.create_trail(
            Name=trail_name_eu, S3BucketName=bucket_name_eu, IsMultiRegionTrail=False
        )
        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1]
        )
        cloudtrail = Cloudtrail(aws_provider)
        assert len(cloudtrail.trails) == len(aws_provider.identity.audited_regions)
        for trail in cloudtrail.trails.values():
            if trail.name:
                if trail.name == trail_name_us:
                    assert not trail.is_multiregion
                    assert trail.home_region == AWS_REGION_US_EAST_1
                    assert trail.region == AWS_REGION_US_EAST_1
                    assert trail.is_logging
                    assert trail.log_file_validation_enabled
                    assert not trail.latest_cloudwatch_delivery_time
                    assert trail.s3_bucket == bucket_name_us

    @mock_aws
    def test_get_classic_event_selectors(self):
        cloudtrail_client_us_east_1 = client(
            "cloudtrail", region_name=AWS_REGION_US_EAST_1
        )
        s3_client_us_east_1 = client("s3", region_name=AWS_REGION_US_EAST_1)
        trail_name_us = "trail_test_us"
        bucket_name_us = "bucket_test_us"
        s3_client_us_east_1.create_bucket(Bucket=bucket_name_us)
        cloudtrail_client_us_east_1.create_trail(
            Name=trail_name_us,
            S3BucketName=bucket_name_us,
            IsMultiRegionTrail=False,
            EnableLogFileValidation=True,
        )
        cloudtrail_client_us_east_1.start_logging(Name=trail_name_us)
        data_events_response = cloudtrail_client_us_east_1.put_event_selectors(
            TrailName=trail_name_us,
            EventSelectors=[
                {
                    "ReadWriteType": "All",
                    "IncludeManagementEvents": True,
                    "DataResources": [
                        {"Type": "AWS::S3::Object", "Values": ["arn:aws:s3:::*/*"]}
                    ],
                }
            ],
        )["EventSelectors"]
        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1]
        )
        cloudtrail = Cloudtrail(aws_provider)
        assert len(cloudtrail.trails) == len(aws_provider.identity.audited_regions)
        for trail in cloudtrail.trails.values():
            if trail.name:
                if trail.name == trail_name_us:
                    assert not trail.is_multiregion
                    assert trail.home_region == AWS_REGION_US_EAST_1
                    assert trail.region == AWS_REGION_US_EAST_1
                    assert trail.is_logging
                    assert trail.log_file_validation_enabled
                    assert not trail.latest_cloudwatch_delivery_time
                    assert trail.s3_bucket == bucket_name_us
                    assert (
                        trail.data_events[0].event_selector == data_events_response[0]
                    )
                    assert not trail.data_events[0].is_advanced

    @mock_aws
    def test_get_advanced_event_selectors(self):
        cloudtrail_client_us_east_1 = client(
            "cloudtrail", region_name=AWS_REGION_US_EAST_1
        )
        s3_client_us_east_1 = client("s3", region_name=AWS_REGION_US_EAST_1)
        trail_name_us = "trail_test_us"
        bucket_name_us = "bucket_test_us"
        s3_client_us_east_1.create_bucket(Bucket=bucket_name_us)
        cloudtrail_client_us_east_1.create_trail(
            Name=trail_name_us,
            S3BucketName=bucket_name_us,
            IsMultiRegionTrail=False,
            EnableLogFileValidation=True,
        )
        cloudtrail_client_us_east_1.start_logging(Name=trail_name_us)
        data_events_response = cloudtrail_client_us_east_1.put_event_selectors(
            TrailName=trail_name_us,
            AdvancedEventSelectors=[
                {
                    "Name": "test",
                    "FieldSelectors": [
                        {"Field": "eventCategory", "Equals": ["Data"]},
                        {"Field": "resources.type", "Equals": ["AWS::S3::Object"]},
                    ],
                },
            ],
        )["AdvancedEventSelectors"]
        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1]
        )
        cloudtrail = Cloudtrail(aws_provider)
        assert len(cloudtrail.trails) == len(aws_provider.identity.audited_regions)
        for trail in cloudtrail.trails.values():
            if trail.name:
                if trail.name == trail_name_us:
                    assert not trail.is_multiregion
                    assert trail.home_region == AWS_REGION_US_EAST_1
                    assert trail.region == AWS_REGION_US_EAST_1
                    assert trail.is_logging
                    assert trail.log_file_validation_enabled
                    assert not trail.latest_cloudwatch_delivery_time
                    assert trail.s3_bucket == bucket_name_us
                    assert (
                        trail.data_events[0].event_selector == data_events_response[0]
                    )
                    assert trail.data_events[0].is_advanced

    @mock_aws
    def test_lookup_events(self):
        cloudtrail_client_us_east_1 = client(
            "cloudtrail", region_name=AWS_REGION_US_EAST_1
        )
        s3_client_us_east_1 = client("s3", region_name=AWS_REGION_US_EAST_1)
        trail_name_us = "trail_test_us"
        bucket_name_us = "bucket_test_us"
        s3_client_us_east_1.create_bucket(Bucket=bucket_name_us)
        cloudtrail_client_us_east_1.create_trail(
            Name=trail_name_us,
            S3BucketName=bucket_name_us,
            IsMultiRegionTrail=False,
            EnableLogFileValidation=True,
        )
        cloudtrail_client_us_east_1.start_logging(Name=trail_name_us)
        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1]
        )
        cloudtrail = Cloudtrail(aws_provider)
        assert len(cloudtrail.trails) == len(aws_provider.identity.audited_regions)

    @mock_aws
    def test_list_tags_for_resource(self):
        tag = "test-tag"
        cloudtrail_client_us_east_1 = client(
            "cloudtrail", region_name=AWS_REGION_US_EAST_1
        )
        s3_client_us_east_1 = client("s3", region_name=AWS_REGION_US_EAST_1)
        trail_name_us = "trail_test_us"
        bucket_name_us = "bucket_test_us"
        s3_client_us_east_1.create_bucket(Bucket=bucket_name_us)
        cloudtrail_client_us_east_1.create_trail(
            Name=trail_name_us,
            S3BucketName=bucket_name_us,
            IsMultiRegionTrail=False,
            EnableLogFileValidation=True,
            TagsList=[
                {"Key": "test", "Value": tag},
            ],
        )
        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1]
        )
        cloudtrail = Cloudtrail(aws_provider)
        assert len(cloudtrail.trails) == len(aws_provider.identity.audited_regions)
        for trail in cloudtrail.trails.values():
            if trail.name:
                if trail.name == trail_name_us:
                    assert trail.tags == [{"Key": "test", "Value": tag}]


class Test_normalize_cloudtrail_identity:
    def test_iam_user_with_path(self):
        identity_arn = (
            f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:user/engineering/platform/attacker"
        )

        resource = normalize_cloudtrail_identity(
            {"type": "IAMUser", "arn": identity_arn}, AWS_REGION_US_EAST_1
        )

        assert resource.id == "user/engineering/platform/attacker"
        assert resource.name == "attacker"
        assert resource.arn == identity_arn
        assert resource.region == AWS_REGION_US_EAST_1
        assert resource.identity_type == "IAMUser"
        assert resource.source_arn == identity_arn

    def test_assumed_role_with_session_issuer(self):
        source_arn = (
            f"arn:aws:sts::{AWS_ACCOUNT_NUMBER}:assumed-role/platform/admin/session-one"
        )
        role_arn = f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:role/platform/admin"

        resource = normalize_cloudtrail_identity(
            {
                "type": "AssumedRole",
                "arn": source_arn,
                "sessionContext": {"sessionIssuer": {"arn": role_arn}},
            },
            AWS_REGION_US_EAST_1,
        )

        assert resource.id == "role/platform/admin"
        assert resource.name == "admin"
        assert resource.arn == role_arn
        assert resource.identity_type == "AssumedRole"
        assert resource.source_arn == source_arn

    def test_assumed_role_without_session_issuer(self):
        source_arn = (
            f"arn:aws:sts::{AWS_ACCOUNT_NUMBER}:assumed-role/platform-admin/session-one"
        )

        resource = normalize_cloudtrail_identity(
            {"type": "AssumedRole", "arn": source_arn}, AWS_REGION_US_EAST_1
        )

        assert resource.id == "assumed-role/platform-admin/session-one"
        assert resource.name == "platform-admin"
        assert resource.arn == source_arn
        assert resource.source_arn == source_arn

    def test_user_and_role_with_same_leaf_name_are_distinct(self):
        user = normalize_cloudtrail_identity(
            {
                "type": "IAMUser",
                "arn": f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:user/team/operator",
            },
            AWS_REGION_US_EAST_1,
        )
        role = normalize_cloudtrail_identity(
            {
                "type": "AssumedRole",
                "arn": f"arn:aws:sts::{AWS_ACCOUNT_NUMBER}:assumed-role/operator/session",
                "sessionContext": {
                    "sessionIssuer": {
                        "arn": f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:role/team/operator"
                    }
                },
            },
            AWS_REGION_US_EAST_1,
        )

        assert user.id == "user/team/operator"
        assert role.id == "role/team/operator"

    def test_roles_with_same_session_name_are_distinct(self):
        first_role = normalize_cloudtrail_identity(
            {
                "type": "AssumedRole",
                "arn": f"arn:aws:sts::{AWS_ACCOUNT_NUMBER}:assumed-role/first/shared-session",
                "sessionContext": {
                    "sessionIssuer": {
                        "arn": f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:role/first"
                    }
                },
            },
            AWS_REGION_US_EAST_1,
        )
        second_role = normalize_cloudtrail_identity(
            {
                "type": "AssumedRole",
                "arn": f"arn:aws:sts::{AWS_ACCOUNT_NUMBER}:assumed-role/second/shared-session",
                "sessionContext": {
                    "sessionIssuer": {
                        "arn": f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:role/second"
                    }
                },
            },
            AWS_REGION_US_EAST_1,
        )

        assert first_role.id == "role/first"
        assert second_role.id == "role/second"

    def test_federated_user(self):
        identity_arn = f"arn:aws:sts::{AWS_ACCOUNT_NUMBER}:federated-user/external-user"

        resource = normalize_cloudtrail_identity(
            {"type": "FederatedUser", "arn": identity_arn},
            AWS_REGION_US_EAST_1,
        )

        assert resource.id == "federated-user/external-user"
        assert resource.name == "external-user"
        assert resource.arn == identity_arn

    def test_root(self):
        identity_arn = f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root"

        resource = normalize_cloudtrail_identity(
            {"type": "Root", "arn": identity_arn}, AWS_REGION_US_EAST_1
        )

        assert resource.id == "root"
        assert resource.name == "root"
        assert resource.arn == identity_arn

    def test_unknown_identity_with_arn(self):
        identity_arn = (
            f"arn:aws:custom:us-east-1:{AWS_ACCOUNT_NUMBER}:resource/path/name"
        )

        resource = normalize_cloudtrail_identity(
            {"type": "UnknownType", "arn": identity_arn}, AWS_REGION_US_EAST_1
        )

        assert resource.id == "resource/path/name"
        assert resource.name == "name"
        assert resource.arn == identity_arn

    def test_identity_without_arn_is_ignored(self):
        assert (
            normalize_cloudtrail_identity({"type": "AWSService"}, AWS_REGION_US_EAST_1)
            is None
        )


class Test_get_cloudtrail_threat_detection_identities:
    def test_same_role_sessions_aggregate_by_canonical_role_arn(self):
        role_arn = f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:role/platform/admin"
        cloudtrail_client = mock.MagicMock()
        cloudtrail_client.region = AWS_REGION_US_EAST_1
        cloudtrail_client.trails = {"trail": mock.MagicMock(is_multiregion=False)}

        def lookup_events(trail, event_name, minutes):
            session_name = "session-one" if event_name == "ActionOne" else "session-two"
            return [
                {
                    "CloudTrailEvent": json.dumps(
                        {
                            "userIdentity": {
                                "type": "AssumedRole",
                                "arn": f"arn:aws:sts::{AWS_ACCOUNT_NUMBER}:assumed-role/admin/{session_name}",
                                "sessionContext": {"sessionIssuer": {"arn": role_arn}},
                            }
                        }
                    )
                }
            ]

        cloudtrail_client._lookup_events = lookup_events

        identities = get_cloudtrail_threat_detection_identities(
            cloudtrail_client, ["ActionOne", "ActionTwo"], 60
        )

        assert list(identities) == [role_arn]
        resource, actions = identities[role_arn]
        assert resource.id == "role/platform/admin"
        assert actions == {"ActionOne", "ActionTwo"}

    def test_different_roles_with_same_session_name_remain_distinct(self):
        first_role_arn = f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:role/first"
        second_role_arn = f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:role/second"
        cloudtrail_client = mock.MagicMock()
        cloudtrail_client.region = AWS_REGION_US_EAST_1
        cloudtrail_client.trails = {"trail": mock.MagicMock(is_multiregion=False)}
        cloudtrail_client._lookup_events = lambda trail, event_name, minutes: [
            {
                "CloudTrailEvent": json.dumps(
                    {
                        "userIdentity": {
                            "type": "AssumedRole",
                            "arn": f"arn:aws:sts::{AWS_ACCOUNT_NUMBER}:assumed-role/first/shared-session",
                            "sessionContext": {
                                "sessionIssuer": {"arn": first_role_arn}
                            },
                        }
                    }
                )
            },
            {
                "CloudTrailEvent": json.dumps(
                    {
                        "userIdentity": {
                            "type": "AssumedRole",
                            "arn": f"arn:aws:sts::{AWS_ACCOUNT_NUMBER}:assumed-role/second/shared-session",
                            "sessionContext": {
                                "sessionIssuer": {"arn": second_role_arn}
                            },
                        }
                    }
                )
            },
        ]

        identities = get_cloudtrail_threat_detection_identities(
            cloudtrail_client, ["ActionOne"], 60
        )

        assert set(identities) == {first_role_arn, second_role_arn}
