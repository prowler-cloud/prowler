import re

from rest_framework_json_api import serializers


class OpenAICredentialsSerializer(serializers.Serializer):
    api_key = serializers.CharField()

    def validate_api_key(self, value: str) -> str:
        pattern = r"^sk-[\w-]+$"
        if not re.match(pattern, value or ""):
            raise serializers.ValidationError("Invalid OpenAI API key format.")
        return value


class BedrockCredentialsSerializer(serializers.Serializer):
    """
    Serializer for AWS Bedrock credentials validation.

    Validates long-term AWS credentials (AKIA) and region format.
    """

    access_key_id = serializers.CharField()
    secret_access_key = serializers.CharField()
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

    def validate_region(self, value: str) -> str:
        """Validate AWS region format."""
        pattern = r"^[a-z]{2}-[a-z]+-\d+$"
        if not re.match(pattern, value or ""):
            raise serializers.ValidationError(
                "Invalid AWS region format. Expected format like 'us-east-1' or 'eu-west-2'."
            )
        return value


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
