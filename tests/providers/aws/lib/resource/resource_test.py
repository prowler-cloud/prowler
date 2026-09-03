import pytest
from pydantic import ValidationError

# Adjust the import path as needed for your project layout
from prowler.lib.resource.resource import Resource
from prowler.providers.aws.lib.resource.resource import _ARN_PATTERN, AWSResource

# Sample ARNs for testing
VALID_S3_ARN = "arn:aws:s3:eu-central-1:123456789012:bucket/my-bucket"
VALID_LAMBDA_ARN = "arn:aws:lambda:us-east-1:123456789012:function:my-function"
INVALID_ARN = "arn:aws::123456:badformat"


class TestAWSResource:
    def test_arn_regex_matches(self):
        """Ensure the regex itself captures the expected groups."""
        m = _ARN_PATTERN.match(VALID_S3_ARN)
        assert m
        assert m.group("service") == "s3"
        assert m.group("region") == "eu-central-1"
        assert m.group("resource_id") == "bucket/my-bucket"

    @pytest.mark.parametrize(
        "arn,expected_service,expected_region,expected_id",
        [
            (VALID_S3_ARN, "s3", "eu-central-1", "bucket/my-bucket"),
            (VALID_LAMBDA_ARN, "lambda", "us-east-1", "function:my-function"),
        ],
    )
    def test_populate_from_arn_defaults(
        self, arn, expected_service, expected_region, expected_id
    ):
        """Fields service, region, and id should be auto‐filled from the ARN."""
        resource = AWSResource(arn=arn)
        assert isinstance(resource, Resource)
        assert resource.service == expected_service
        assert resource.region == expected_region
        assert resource.id == expected_id

    def test_override_service_and_region_and_id(self):
        """Explicitly provided values should override ARN‐derived defaults."""
        resource = AWSResource(
            arn=VALID_S3_ARN,
            service="override-service",
            region="override-region",
            id="override-id",
        )
        assert resource.service == "override-service"
        assert resource.region == "override-region"
        assert resource.id == "override-id"

    def test_missing_arn_raises_error(self):
        """If no ARN is given, an error is raised."""

        with pytest.raises(ValidationError) as excinfo:
            AWSResource(
                service="manual-service", region="manual-region", id="manual-id"
            )
        assert (
            "1 validation error for AWSResource\narn\n  field required (type=value_error.missing)"
            in str(excinfo.value)
        )

    def test_empty_region_raises_error(self):
        """An explicitly empty region (or an ARN with empty region) should error."""
        # Empty string region
        with pytest.raises(ValidationError) as excinfo:
            AWSResource(arn=None, service="s3", region="")
        assert "region cannot be empty" in str(excinfo.value)

        # ARN with missing region segment
        bad_arn = "arn:aws:s3::123456789012:bucket/x"
        with pytest.raises(ValidationError) as excinfo2:
            AWSResource(arn=bad_arn)
        # root_validator will run first but region validator will catch empty region
        assert "region cannot be empty" in str(excinfo2.value)

    def test_invalid_arn_raises_value_error(self):
        """Malformed ARN should trigger ValueError from the root_validator."""
        with pytest.raises(ValidationError) as excinfo:
            AWSResource(arn=INVALID_ARN)
        # unwrap to see the inner ValueError message
        err = excinfo.value.errors()[0]
        assert "Invalid ARN" in err["msg"]

    def test_tags_default_and_mutability(self):
        """Ensure tags default to an empty list and are independent per instance."""
        resource_1 = AWSResource(arn=VALID_S3_ARN)
        resource_2 = AWSResource(arn=VALID_S3_ARN)
        assert resource_1.tags == [] and resource_2.tags == []
        resource_1.tags.append("tag1")
        assert resource_2.tags == []

    def test_name_field_passthrough(self):
        """Name should be accepted and stored unchanged."""
        res = AWSResource(arn=VALID_S3_ARN, name="my-name")
        assert res.name == "my-name"
