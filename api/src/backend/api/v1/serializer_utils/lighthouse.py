import re

from drf_spectacular.utils import extend_schema_field
from rest_framework_json_api import serializers


class OpenAICredentialsSerializer(serializers.Serializer):
    api_key = serializers.CharField()

    def validate_api_key(self, value: str) -> str:
        pattern = r"^sk-[\w-]+$"
        if not re.match(pattern, value or ""):
            raise serializers.ValidationError("Invalid OpenAI API key format.")
        return value

    def to_internal_value(self, data):
        """Check for unknown fields before DRF filters them out."""
        if not isinstance(data, dict):
            raise serializers.ValidationError(
                {"non_field_errors": ["Credentials must be an object"]}
            )

        allowed_fields = set(self.fields.keys())
        provided_fields = set(data.keys())
        extra_fields = provided_fields - allowed_fields

        if extra_fields:
            raise serializers.ValidationError(
                {
                    "non_field_errors": [
                        f"Unknown fields in credentials: {', '.join(sorted(extra_fields))}"
                    ]
                }
            )

        return super().to_internal_value(data)


class BedrockCredentialsSerializer(serializers.Serializer):
    """
    Serializer for AWS Bedrock credentials validation.

    Supports two authentication methods:
    1. AWS access key + secret key
    2. Bedrock API key (bearer token)

    In both cases, region is mandatory.
    """

    access_key_id = serializers.CharField(required=False, allow_blank=False)
    secret_access_key = serializers.CharField(required=False, allow_blank=False)
    api_key = serializers.CharField(required=False, allow_blank=False)
    region = serializers.CharField()

    def validate_access_key_id(self, value: str) -> str:
        """Validate AWS access key ID format (AKIA for long-term credentials)."""
        pattern = r"^AKIA[0-9A-Z]{16}$"
        if not re.match(pattern, value or ""):
            raise serializers.ValidationError(
                "Invalid AWS access key ID format. Must be AKIA followed by 16 alphanumeric characters."
            )
        return value

    def validate_secret_access_key(self, value: str) -> str:
        """Validate AWS secret access key format (40 base64 characters)."""
        pattern = r"^[A-Za-z0-9/+=]{40}$"
        if not re.match(pattern, value or ""):
            raise serializers.ValidationError(
                "Invalid AWS secret access key format. Must be 40 base64 characters."
            )
        return value

    def validate_api_key(self, value: str) -> str:
        """
        Validate Bedrock API key (bearer token).
        """
        pattern = r"^ABSKQmVkcm9ja0FQSUtleS[A-Za-z0-9+/=]{110}$"
        if not re.match(pattern, value or ""):
            raise serializers.ValidationError("Invalid Bedrock API key format.")
        return value

    def validate_region(self, value: str) -> str:
        """Validate AWS region format."""
        pattern = r"^[a-z]{2}-[a-z]+-\d+$"
        if not re.match(pattern, value or ""):
            raise serializers.ValidationError(
                "Invalid AWS region format. Expected format like 'us-east-1' or 'eu-west-2'."
            )
        return value

    def validate(self, attrs):
        """
        Enforce either:
        - access_key_id + secret_access_key + region
        OR
        - api_key + region
        """
        access_key_id = attrs.get("access_key_id")
        secret_access_key = attrs.get("secret_access_key")
        api_key = attrs.get("api_key")
        region = attrs.get("region")

        errors = {}

        if not region:
            errors["region"] = ["Region is required."]

        using_access_keys = bool(access_key_id or secret_access_key)
        using_api_key = api_key is not None and api_key != ""

        if using_access_keys and using_api_key:
            errors["non_field_errors"] = [
                "Provide either access key + secret key OR api key, not both."
            ]
        elif not using_access_keys and not using_api_key:
            errors["non_field_errors"] = [
                "You must provide either access key + secret key OR api key."
            ]
        elif using_access_keys:
            # Both access_key_id and secret_access_key must be present together
            if not access_key_id:
                errors.setdefault("access_key_id", []).append(
                    "AWS access key ID is required when using access key authentication."
                )
            if not secret_access_key:
                errors.setdefault("secret_access_key", []).append(
                    "AWS secret access key is required when using access key authentication."
                )

        if errors:
            raise serializers.ValidationError(errors)

        return attrs

    def to_internal_value(self, data):
        """Check for unknown fields before DRF filters them out."""
        if not isinstance(data, dict):
            raise serializers.ValidationError(
                {"non_field_errors": ["Credentials must be an object"]}
            )

        allowed_fields = set(self.fields.keys())
        provided_fields = set(data.keys())
        extra_fields = provided_fields - allowed_fields

        if extra_fields:
            raise serializers.ValidationError(
                {
                    "non_field_errors": [
                        f"Unknown fields in credentials: {', '.join(sorted(extra_fields))}"
                    ]
                }
            )

        return super().to_internal_value(data)


class BedrockCredentialsUpdateSerializer(BedrockCredentialsSerializer):
    """
    Serializer for AWS Bedrock credentials during UPDATE operations.

    Inherits all validation logic from BedrockCredentialsSerializer but makes
    all fields optional to support partial updates.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Make all fields optional for updates
        for field in self.fields.values():
            field.required = False

    def validate(self, attrs):
        """
        For updates, this serializer only checks individual fields.
        It does NOT enforce the "either access keys OR api key" rule.
        That rule is applied later, after merging with existing stored
        credentials, in LighthouseProviderConfigUpdateSerializer.
        """
        return attrs


class OpenAICompatibleCredentialsSerializer(serializers.Serializer):
    """
    Minimal serializer for OpenAI-compatible credentials.

    Many OpenAI-compatible providers do not use the same key format as OpenAI.
    We only require a non-empty API key string. Additional fields can be added later
    without breaking existing configurations.
    """

    api_key = serializers.CharField()

    def validate_api_key(self, value: str) -> str:
        if not isinstance(value, str) or not value.strip():
            raise serializers.ValidationError("API key is required.")
        return value.strip()

    def to_internal_value(self, data):
        """Check for unknown fields before DRF filters them out."""
        if not isinstance(data, dict):
            raise serializers.ValidationError(
                {"non_field_errors": ["Credentials must be an object"]}
            )

        allowed_fields = set(self.fields.keys())
        provided_fields = set(data.keys())
        extra_fields = provided_fields - allowed_fields

        if extra_fields:
            raise serializers.ValidationError(
                {
                    "non_field_errors": [
                        f"Unknown fields in credentials: {', '.join(sorted(extra_fields))}"
                    ]
                }
            )

        return super().to_internal_value(data)


@extend_schema_field(
    {
        "oneOf": [
            {
                "type": "object",
                "title": "OpenAI Credentials",
                "properties": {
                    "api_key": {
                        "type": "string",
                        "description": "OpenAI API key. Must start with 'sk-' followed by alphanumeric characters, "
                        "hyphens, or underscores.",
                        "pattern": "^sk-[\\w-]+$",
                    }
                },
                "required": ["api_key"],
            },
            {
                "title": "AWS Bedrock Credentials",
                "oneOf": [
                    {
                        "title": "IAM Access Key Pair",
                        "type": "object",
                        "description": "Authenticate with AWS access key and secret key. Recommended when you manage IAM users or roles.",
                        "properties": {
                            "access_key_id": {
                                "type": "string",
                                "description": "AWS access key ID.",
                                "pattern": "^AKIA[0-9A-Z]{16}$",
                            },
                            "secret_access_key": {
                                "type": "string",
                                "description": "AWS secret access key.",
                                "pattern": "^[A-Za-z0-9/+=]{40}$",
                            },
                            "region": {
                                "type": "string",
                                "description": "AWS region identifier where Bedrock is available. Examples: us-east-1, "
                                "us-west-2, eu-west-1, ap-northeast-1.",
                                "pattern": "^[a-z]{2}-[a-z]+-\\d+$",
                            },
                        },
                        "required": ["access_key_id", "secret_access_key", "region"],
                    },
                    {
                        "title": "Amazon Bedrock API Key",
                        "type": "object",
                        "description": "Authenticate with an Amazon Bedrock API key (bearer token). Region is still required.",
                        "properties": {
                            "api_key": {
                                "type": "string",
                                "description": "Amazon Bedrock API key (bearer token).",
                            },
                            "region": {
                                "type": "string",
                                "description": "AWS region identifier where Bedrock is available. Examples: us-east-1, "
                                "us-west-2, eu-west-1, ap-northeast-1.",
                                "pattern": "^[a-z]{2}-[a-z]+-\\d+$",
                            },
                        },
                        "required": ["api_key", "region"],
                    },
                ],
            },
            {
                "type": "object",
                "title": "OpenAI Compatible Credentials",
                "properties": {
                    "api_key": {
                        "type": "string",
                        "description": "API key for OpenAI-compatible provider. The format varies by provider. "
                        "Note: The 'base_url' field (separate from credentials) is required when using this provider type.",
                    }
                },
                "required": ["api_key"],
            },
        ]
    }
)
class LighthouseCredentialsField(serializers.JSONField):
    pass
