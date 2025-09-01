import os
import re

from drf_spectacular.utils import extend_schema_field
from rest_framework_json_api import serializers

from api.v1.serializer_utils.base import BaseValidateSerializer


class S3ConfigSerializer(BaseValidateSerializer):
    bucket_name = serializers.CharField()
    output_directory = serializers.CharField(allow_blank=True)

    def validate_output_directory(self, value):
        """
        Validate the output_directory field to ensure it's a properly formatted path.
        Prevents paths with excessive slashes like "///////test".
        If empty, sets a default value.
        """
        # If empty or None, set default value
        if not value:
            return "output"

        # Normalize the path to remove excessive slashes
        normalized_path = os.path.normpath(value)

        # Remove leading slashes for S3 paths
        if normalized_path.startswith("/"):
            normalized_path = normalized_path.lstrip("/")

        # Check for invalid characters or patterns
        if re.search(r'[<>:"|?*]', normalized_path):
            raise serializers.ValidationError(
                'Output directory contains invalid characters. Avoid: < > : " | ? *'
            )

        # Check for empty path after normalization
        if not normalized_path or normalized_path == ".":
            raise serializers.ValidationError(
                "Output directory cannot be empty or just '.' or '/'."
            )

        # Check for paths that are too long (S3 key limit is 1024 characters, leave some room for filename)
        if len(normalized_path) > 900:
            raise serializers.ValidationError(
                "Output directory path is too long (max 900 characters)."
            )

        return normalized_path

    class Meta:
        resource_name = "integrations"


class SecurityHubConfigSerializer(BaseValidateSerializer):
    send_only_fails = serializers.BooleanField(default=False)
    archive_previous_findings = serializers.BooleanField(default=False)
    regions = serializers.DictField(default=dict, read_only=True)

    def to_internal_value(self, data):
        validated_data = super().to_internal_value(data)
        # Always initialize regions as empty dict
        validated_data["regions"] = {}
        return validated_data

    class Meta:
        resource_name = "integrations"


class JiraConfigSerializer(BaseValidateSerializer):
    project_key = serializers.CharField(required=True)
    domain = serializers.CharField(required=True)
    issue_types = serializers.ListField(required=False, child=serializers.CharField())
    issue_labels = serializers.ListField(required=False, child=serializers.CharField())

    class Meta:
        resource_name = "integrations"


class AWSCredentialSerializer(BaseValidateSerializer):
    role_arn = serializers.CharField(required=False)
    external_id = serializers.CharField(required=False)
    role_session_name = serializers.CharField(required=False)
    session_duration = serializers.IntegerField(
        required=False, min_value=900, max_value=43200
    )
    aws_access_key_id = serializers.CharField(required=False)
    aws_secret_access_key = serializers.CharField(required=False)
    aws_session_token = serializers.CharField(required=False)

    class Meta:
        resource_name = "integrations"


class JiraCredentialSerializer(BaseValidateSerializer):
    user_mail = serializers.EmailField(required=True)
    api_token = serializers.CharField(required=True)

    class Meta:
        resource_name = "integrations"


@extend_schema_field(
    {
        "oneOf": [
            {
                "type": "object",
                "title": "AWS Credentials",
                "properties": {
                    "role_arn": {
                        "type": "string",
                        "description": "The Amazon Resource Name (ARN) of the role to assume. Required for AWS role "
                        "assumption.",
                    },
                    "external_id": {
                        "type": "string",
                        "description": "An identifier to enhance security for role assumption.",
                    },
                    "aws_access_key_id": {
                        "type": "string",
                        "description": "The AWS access key ID. Only required if the environment lacks pre-configured "
                        "AWS credentials.",
                    },
                    "aws_secret_access_key": {
                        "type": "string",
                        "description": "The AWS secret access key. Required if 'aws_access_key_id' is provided or if "
                        "no AWS credentials are pre-configured.",
                    },
                    "aws_session_token": {
                        "type": "string",
                        "description": "The session token for temporary credentials, if applicable.",
                    },
                    "session_duration": {
                        "type": "integer",
                        "minimum": 900,
                        "maximum": 43200,
                        "default": 3600,
                        "description": "The duration (in seconds) for the role session.",
                    },
                    "role_session_name": {
                        "type": "string",
                        "description": "An identifier for the role session, useful for tracking sessions in AWS logs. "
                        "The regex used to validate this parameter is a string of characters consisting of "
                        "upper- and lower-case alphanumeric characters with no spaces. You can also include "
                        "underscores or any of the following characters: =,.@-\n\n"
                        "Examples:\n"
                        "- MySession123\n"
                        "- User_Session-1\n"
                        "- Test.Session@2",
                        "pattern": "^[a-zA-Z0-9=,.@_-]+$",
                    },
                },
            },
            {
                "type": "object",
                "title": "JIRA Credentials",
                "properties": {
                    "user_mail": {
                        "type": "string",
                        "format": "email",
                        "description": "The email address of the JIRA user account.",
                    },
                    "api_token": {
                        "type": "string",
                        "description": "The API token for authentication with JIRA. This can be generated from your "
                        "Atlassian account settings.",
                    },
                },
                "required": ["user_mail", "api_token"],
            },
        ]
    }
)
class IntegrationCredentialField(serializers.JSONField):
    pass


@extend_schema_field(
    {
        "oneOf": [
            {
                "type": "object",
                "title": "Amazon S3",
                "properties": {
                    "bucket_name": {
                        "type": "string",
                        "description": "The name of the S3 bucket where files will be stored.",
                    },
                    "output_directory": {
                        "type": "string",
                        "description": "The directory path within the bucket where files will be saved. Optional - "
                        'defaults to "output" if not provided. Path will be normalized to remove '
                        'excessive slashes and invalid characters are not allowed (< > : " | ? *). '
                        "Maximum length is 900 characters.",
                        "maxLength": 900,
                        "pattern": '^[^<>:"|?*]+$',
                        "default": "output",
                    },
                },
                "required": ["bucket_name"],
            },
            {
                "type": "object",
                "title": "AWS Security Hub",
                "properties": {
                    "send_only_fails": {
                        "type": "boolean",
                        "default": False,
                        "description": "If true, only findings with status 'FAIL' will be sent to Security Hub.",
                    },
                    "archive_previous_findings": {
                        "type": "boolean",
                        "default": False,
                        "description": "If true, archives findings that are not present in the current execution.",
                    },
                },
            },
            {
                "type": "object",
                "title": "JIRA",
                "properties": {
                    "project_key": {
                        "type": "string",
                        "description": "The JIRA project key where issues will be created (e.g., 'PROJ', 'SEC').",
                    },
                    "domain": {
                        "type": "string",
                        "description": "The JIRA domain/instance URL (e.g., 'your-domain.atlassian.net').",
                    },
                    "issue_types": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "List of JIRA issue types to create for findings.",
                    },
                    "issue_labels": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "List of labels to apply to created JIRA issues..",
                    },
                },
                "required": ["project_key", "domain"],
            },
        ]
    }
)
class IntegrationConfigField(serializers.JSONField):
    pass
