from drf_spectacular.utils import extend_schema_field
from rest_framework_json_api import serializers

from api.v1.serializer_utils.base import BaseValidateSerializer


class S3ConfigSerializer(BaseValidateSerializer):
    bucket_name = serializers.CharField()
    output_directory = serializers.CharField()

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
                        "description": "The directory path within the bucket where files will be saved.",
                    },
                },
                "required": ["bucket_name", "output_directory"],
            },
        ]
    }
)
class IntegrationConfigField(serializers.JSONField):
    pass
