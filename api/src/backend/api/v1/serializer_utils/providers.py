from drf_spectacular.utils import extend_schema_field
from rest_framework_json_api import serializers


@extend_schema_field(
    {
        "oneOf": [
            {
                "type": "object",
                "title": "AWS Static Credentials",
                "properties": {
                    "aws_access_key_id": {
                        "type": "string",
                        "description": "The AWS access key ID. Required for environments where no IAM role is being "
                        "assumed and direct AWS access is needed.",
                    },
                    "aws_secret_access_key": {
                        "type": "string",
                        "description": "The AWS secret access key. Must accompany 'aws_access_key_id' to authorize "
                        "access to AWS resources.",
                    },
                    "aws_session_token": {
                        "type": "string",
                        "description": "The session token associated with temporary credentials. Only needed for "
                        "session-based or temporary AWS access.",
                    },
                },
                "required": ["aws_access_key_id", "aws_secret_access_key"],
            },
            {
                "type": "object",
                "title": "AWS Assume Role",
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
                "required": ["role_arn", "external_id"],
            },
            {
                "type": "object",
                "title": "Azure Static Credentials",
                "properties": {
                    "client_id": {
                        "type": "string",
                        "description": "The Azure application (client) ID for authentication in Azure AD.",
                    },
                    "client_secret": {
                        "type": "string",
                        "description": "The client secret associated with the application (client) ID, providing "
                        "secure access.",
                    },
                    "tenant_id": {
                        "type": "string",
                        "description": "The Azure tenant ID, representing the directory where the application is "
                        "registered.",
                    },
                },
                "required": ["client_id", "client_secret", "tenant_id"],
            },
            {
                "type": "object",
                "title": "M365 Static Credentials",
                "properties": {
                    "client_id": {
                        "type": "string",
                        "description": "The Azure application (client) ID for authentication in Azure AD.",
                    },
                    "tenant_id": {
                        "type": "string",
                        "description": "The Azure tenant ID, representing the directory where the application is "
                        "registered.",
                    },
                    "client_secret": {
                        "type": "string",
                        "description": "The client secret associated with the application (client) ID, providing "
                        "secure access.",
                    },
                    "user": {
                        "type": "email",
                        "description": "User microsoft email address.",
                        "deprecated": True,
                    },
                    "password": {
                        "type": "string",
                        "description": "User password.",
                        "deprecated": True,
                    },
                },
                "required": [
                    "client_id",
                    "client_secret",
                    "tenant_id",
                    "user",
                    "password",
                ],
            },
            {
                "type": "object",
                "title": "M365 Certificate Credentials",
                "properties": {
                    "client_id": {
                        "type": "string",
                        "description": "The Azure application (client) ID for authentication in Azure AD.",
                    },
                    "tenant_id": {
                        "type": "string",
                        "description": "The Azure tenant ID, representing the directory where the application is "
                        "registered.",
                    },
                    "certificate_content": {
                        "type": "string",
                        "description": "The certificate content in base64 format for certificate-based authentication.",
                    },
                },
                "required": [
                    "client_id",
                    "tenant_id",
                    "certificate_content",
                ],
            },
            {
                "type": "object",
                "title": "GCP Static Credentials",
                "properties": {
                    "client_id": {
                        "type": "string",
                        "description": "The client ID from Google Cloud, used to identify the application for GCP "
                        "access.",
                    },
                    "client_secret": {
                        "type": "string",
                        "description": "The client secret associated with the GCP client ID, required for secure "
                        "access.",
                    },
                    "refresh_token": {
                        "type": "string",
                        "description": "A refresh token that allows the application to obtain new access tokens for "
                        "extended use.",
                    },
                },
                "required": ["client_id", "client_secret", "refresh_token"],
            },
            {
                "type": "object",
                "title": "GCP Service Account Key",
                "properties": {
                    "service_account_key": {
                        "type": "object",
                        "description": "The service account key for GCP.",
                    }
                },
                "required": ["service_account_key"],
            },
            {
                "type": "object",
                "title": "Kubernetes Static Credentials",
                "properties": {
                    "kubeconfig_content": {
                        "type": "string",
                        "description": "The content of the Kubernetes kubeconfig file, encoded as a string.",
                    }
                },
                "required": ["kubeconfig_content"],
            },
            {
                "type": "object",
                "title": "GitHub Personal Access Token",
                "properties": {
                    "personal_access_token": {
                        "type": "string",
                        "description": "GitHub personal access token for authentication.",
                    }
                },
                "required": ["personal_access_token"],
            },
            {
                "type": "object",
                "title": "GitHub OAuth App Token",
                "properties": {
                    "oauth_app_token": {
                        "type": "string",
                        "description": "GitHub OAuth App token for authentication.",
                    }
                },
                "required": ["oauth_app_token"],
            },
            {
                "type": "object",
                "title": "GitHub App Credentials",
                "properties": {
                    "github_app_id": {
                        "type": "integer",
                        "description": "GitHub App ID for authentication.",
                    },
                    "github_app_key": {
                        "type": "string",
                        "description": "Path to the GitHub App private key file.",
                    },
                },
                "required": ["github_app_id", "github_app_key"],
            },
            {
                "type": "object",
                "title": "IaC Repository Credentials",
                "properties": {
                    "repository_url": {
                        "type": "string",
                        "description": "Repository URL to scan for IaC files.",
                    },
                    "access_token": {
                        "type": "string",
                        "description": "Optional access token for private repositories.",
                    },
                },
                "required": ["repository_url"],
            },
            {
                "type": "object",
                "title": "Oracle Cloud Infrastructure (OCI) API Key Credentials",
                "properties": {
                    "user": {
                        "type": "string",
                        "description": "The OCID of the user to authenticate with.",
                    },
                    "fingerprint": {
                        "type": "string",
                        "description": "The fingerprint of the API signing key.",
                    },
                    "key_file": {
                        "type": "string",
                        "description": "The path to the private key file for API signing. Either key_file or key_content must be provided.",
                    },
                    "key_content": {
                        "type": "string",
                        "description": "The content of the private key for API signing (base64 encoded). Either key_file or key_content must be provided.",
                    },
                    "tenancy": {
                        "type": "string",
                        "description": "The OCID of the tenancy.",
                    },
                    "region": {
                        "type": "string",
                        "description": "The OCI region identifier (e.g., us-ashburn-1, us-phoenix-1).",
                    },
                    "pass_phrase": {
                        "type": "string",
                        "description": "The passphrase for the private key, if encrypted.",
                    },
                },
                "required": ["user", "fingerprint", "tenancy", "region"],
            },
            {
                "type": "object",
                "title": "MongoDB Atlas API Key",
                "properties": {
                    "atlas_public_key": {
                        "type": "string",
                        "description": "MongoDB Atlas API public key.",
                    },
                    "atlas_private_key": {
                        "type": "string",
                        "description": "MongoDB Atlas API private key.",
                    },
                },
                "required": ["atlas_public_key", "atlas_private_key"],
            },
            {
                "type": "object",
                "title": "Alibaba Cloud Static Credentials",
                "properties": {
                    "access_key_id": {
                        "type": "string",
                        "description": "The Alibaba Cloud access key ID for authentication.",
                    },
                    "access_key_secret": {
                        "type": "string",
                        "description": "The Alibaba Cloud access key secret for authentication.",
                    },
                    "security_token": {
                        "type": "string",
                        "description": "The STS security token for temporary credentials (optional).",
                    },
                },
                "required": ["access_key_id", "access_key_secret"],
            },
            {
                "type": "object",
                "title": "Alibaba Cloud RAM Role Assumption",
                "properties": {
                    "role_arn": {
                        "type": "string",
                        "description": "The ARN of the RAM role to assume (e.g., acs:ram::1234567890123456:role/ProwlerRole).",
                    },
                    "access_key_id": {
                        "type": "string",
                        "description": "The Alibaba Cloud access key ID of the RAM user that will assume the role.",
                    },
                    "access_key_secret": {
                        "type": "string",
                        "description": "The Alibaba Cloud access key secret of the RAM user that will assume the role.",
                    },
                    "role_session_name": {
                        "type": "string",
                        "description": "An identifier for the role session (optional, defaults to 'ProwlerSession').",
                    },
                },
                "required": ["role_arn", "access_key_id", "access_key_secret"],
            },
            {
                "type": "object",
                "title": "Cloudflare API Token",
                "properties": {
                    "api_token": {
                        "type": "string",
                        "description": "Cloudflare API Token for authentication (recommended).",
                    },
                },
                "required": ["api_token"],
            },
            {
                "type": "object",
                "title": "Cloudflare API Key + Email",
                "properties": {
                    "api_key": {
                        "type": "string",
                        "description": "Cloudflare Global API Key for authentication (legacy).",
                    },
                    "api_email": {
                        "type": "string",
                        "format": "email",
                        "description": "Email address associated with the Cloudflare account.",
                    },
                },
                "required": ["api_key", "api_email"],
            },
        ]
    }
)
class ProviderSecretField(serializers.JSONField):
    pass
