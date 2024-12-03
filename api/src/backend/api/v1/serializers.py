import json
from datetime import datetime, timedelta, timezone

from django.conf import settings
from django.contrib.auth import authenticate
from django.contrib.auth.models import update_last_login
from django.contrib.auth.password_validation import validate_password
from drf_spectacular.utils import extend_schema_field
from jwt.exceptions import InvalidKeyError
from rest_framework_json_api import serializers
from rest_framework_json_api.serializers import ValidationError
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework_simplejwt.tokens import RefreshToken

from api.models import (
    ComplianceOverview,
    Finding,
    Invitation,
    Membership,
    Provider,
    ProviderGroup,
    ProviderGroupMembership,
    ProviderSecret,
    Resource,
    ResourceTag,
    Scan,
    StateChoices,
    Task,
    User,
)
from api.rls import Tenant

# Tokens


class TokenSerializer(TokenObtainPairSerializer):
    email = serializers.EmailField(write_only=True)
    password = serializers.CharField(write_only=True)
    tenant_id = serializers.UUIDField(
        write_only=True,
        required=False,
        help_text="If not provided, the tenant ID of the first membership that was added"
        " to the user will be used.",
    )

    # Output tokens
    refresh = serializers.CharField(read_only=True)
    access = serializers.CharField(read_only=True)

    class JSONAPIMeta:
        resource_name = "tokens"

    def validate(self, attrs):
        email = attrs.get("email")
        password = attrs.get("password")
        tenant_id = str(attrs.get("tenant_id", ""))

        # Authenticate user
        user = authenticate(username=email, password=password)
        if user is None:
            raise ValidationError("Invalid credentials")

        if tenant_id:
            if not user.is_member_of_tenant(tenant_id):
                raise ValidationError("Tenant does not exist or user is not a member.")
        else:
            first_membership = user.memberships.order_by("date_joined").first()
            if first_membership is None:
                raise ValidationError("User has no memberships.")
            tenant_id = str(first_membership.tenant_id)

        # Generate tokens
        try:
            refresh = RefreshToken.for_user(user)
        except InvalidKeyError:
            # Handle invalid key error
            raise ValidationError(
                {
                    "detail": "Token generation failed due to invalid key configuration. Provide valid "
                    "DJANGO_TOKEN_SIGNING_KEY and DJANGO_TOKEN_VERIFYING_KEY in the environment."
                }
            )
        except Exception as e:
            raise ValidationError({"detail": str(e)})

        # Post-process the tokens
        # Set the tenant_id
        refresh["tenant_id"] = tenant_id

        # Set the nbf (not before) claim to the iat (issued at) claim. At this moment, simplejwt does not provide a
        # way to set the nbf claim
        refresh.payload["nbf"] = refresh["iat"]

        # Get the access token
        access = refresh.access_token

        if settings.SIMPLE_JWT["UPDATE_LAST_LOGIN"]:
            update_last_login(None, user)

        return {"access": str(access), "refresh": str(refresh)}


# TODO: Check if we can change the parent class to TokenRefreshSerializer from rest_framework_simplejwt.serializers
class TokenRefreshSerializer(serializers.Serializer):
    refresh = serializers.CharField()

    # Output token
    access = serializers.CharField(read_only=True)

    class JSONAPIMeta:
        resource_name = "tokens-refresh"

    def validate(self, attrs):
        refresh_token = attrs.get("refresh")

        try:
            # Validate the refresh token
            refresh = RefreshToken(refresh_token)
            # Generate new access token
            access_token = refresh.access_token

            if settings.SIMPLE_JWT["ROTATE_REFRESH_TOKENS"]:
                if settings.SIMPLE_JWT["BLACKLIST_AFTER_ROTATION"]:
                    try:
                        refresh.blacklist()
                    except AttributeError:
                        pass

                refresh.set_jti()
                refresh.set_exp()
                refresh.set_iat()

            return {"access": str(access_token), "refresh": str(refresh)}
        except TokenError:
            raise ValidationError({"refresh": "Invalid or expired token"})


# Base


class BaseSerializerV1(serializers.ModelSerializer):
    def get_root_meta(self, _resource, _many):
        return {"version": "v1"}


class BaseWriteSerializer(BaseSerializerV1):
    def validate(self, data):
        if hasattr(self, "initial_data"):
            initial_data = set(self.initial_data.keys()) - {"id", "type"}
            unknown_keys = initial_data - set(self.fields.keys())
            if unknown_keys:
                raise ValidationError(f"Invalid fields: {unknown_keys}")
        return data


class RLSSerializer(BaseSerializerV1):
    def create(self, validated_data):
        tenant_id = self.context.get("tenant_id")
        validated_data["tenant_id"] = tenant_id
        return super().create(validated_data)


class StateEnumSerializerField(serializers.ChoiceField):
    def __init__(self, **kwargs):
        kwargs["choices"] = StateChoices.choices
        super().__init__(**kwargs)


# Users


class UserSerializer(BaseSerializerV1):
    """
    Serializer for the User model.
    """

    memberships = serializers.ResourceRelatedField(many=True, read_only=True)

    class Meta:
        model = User
        fields = ["id", "name", "email", "company_name", "date_joined", "memberships"]


class UserCreateSerializer(BaseWriteSerializer):
    password = serializers.CharField(write_only=True)
    company_name = serializers.CharField(required=False)

    class Meta:
        model = User
        fields = ["name", "password", "email", "company_name"]

    def validate_password(self, value):
        user = User(**{k: v for k, v in self.initial_data.items() if k != "type"})
        validate_password(value, user=user)
        return value

    def validate_email(self, value):
        normalized_email = value.strip().lower()
        if User.objects.filter(email__iexact=normalized_email).exists():
            raise ValidationError(
                User._meta.get_field("email").error_messages["unique"], code="unique"
            )
        return value

    def create(self, validated_data):
        password = validated_data.pop("password")
        user = User(**validated_data)

        validate_password(password, user=user)
        user.set_password(password)
        user.save()
        return user


class UserUpdateSerializer(BaseWriteSerializer):
    password = serializers.CharField(write_only=True, required=False)

    class Meta:
        model = User
        fields = ["id", "name", "password", "email", "company_name"]
        extra_kwargs = {
            "id": {"read_only": True},
        }

    def validate_password(self, value):
        validate_password(value, user=self.instance)
        return value

    def update(self, instance, validated_data):
        password = validated_data.pop("password", None)
        if password:
            validate_password(password, user=instance)
            instance.set_password(password)
        return super().update(instance, validated_data)


# Tasks
class TaskBase(serializers.ModelSerializer):
    state_mapping = {
        "PENDING": StateChoices.AVAILABLE,
        "STARTED": StateChoices.EXECUTING,
        "PROGRESS": StateChoices.EXECUTING,
        "SUCCESS": StateChoices.COMPLETED,
        "FAILURE": StateChoices.FAILED,
        "REVOKED": StateChoices.CANCELLED,
    }

    class Meta:
        fields = ["id"]
        model = Task

    def map_state(self, task_result_state):
        return self.state_mapping.get(task_result_state, StateChoices.AVAILABLE)

    @extend_schema_field(
        {
            "type": "string",
            "enum": StateChoices.values,
        }
    )
    def get_state(self, obj):
        task_result_state = (
            obj.task_runner_task.status if obj.task_runner_task else None
        )
        return self.map_state(task_result_state)


class TaskSerializer(RLSSerializer, TaskBase):
    state = serializers.SerializerMethodField(read_only=True)
    metadata = serializers.SerializerMethodField(read_only=True)
    result = serializers.SerializerMethodField(read_only=True)
    task_args = serializers.SerializerMethodField(read_only=True)

    completed_at = serializers.DateTimeField(
        source="task_runner_task.date_done", read_only=True
    )
    name = serializers.CharField(source="task_runner_task.task_name", read_only=True)

    class Meta:
        model = Task
        fields = [
            "id",
            "inserted_at",
            "completed_at",
            "name",
            "state",
            "result",
            "task_args",
            "metadata",
        ]

    @extend_schema_field(serializers.JSONField())
    def get_metadata(self, obj):
        return self.get_json_field(obj, "metadata")

    @extend_schema_field(serializers.JSONField())
    def get_result(self, obj):
        return self.get_json_field(obj, "result")

    @extend_schema_field(serializers.JSONField())
    def get_task_args(self, obj):
        task_args = self.get_json_field(obj, "task_kwargs")
        # Celery task_kwargs are stored as a double string JSON in the database when not empty
        if isinstance(task_args, str):
            task_args = json.loads(task_args.replace("'", '"').replace("None", "null"))
        # Remove tenant_id from task_kwargs if present
        task_args.pop("tenant_id", None)

        return task_args

    @staticmethod
    def get_json_field(obj, field_name):
        """Helper method to DRY the logic for loading JSON fields from task_runner_task."""
        task_result_field = (
            getattr(obj.task_runner_task, field_name, None)
            if obj.task_runner_task
            else None
        )
        return json.loads(task_result_field) if task_result_field else {}


# Tenants


class TenantSerializer(BaseSerializerV1):
    """
    Serializer for the Tenant model.
    """

    memberships = serializers.ResourceRelatedField(many=True, read_only=True)

    class Meta:
        model = Tenant
        fields = ["id", "name", "memberships"]


# Memberships


class MemberRoleEnumSerializerField(serializers.ChoiceField):
    def __init__(self, **kwargs):
        kwargs["choices"] = Membership.RoleChoices.choices
        super().__init__(**kwargs)


class MembershipSerializer(serializers.ModelSerializer):
    role = MemberRoleEnumSerializerField()
    user = serializers.HyperlinkedRelatedField(view_name="user-detail", read_only=True)
    tenant = serializers.HyperlinkedRelatedField(
        view_name="tenant-detail", read_only=True
    )

    class Meta:
        model = Membership
        fields = ["id", "user", "tenant", "role", "date_joined"]


# Provider Groups
class ProviderGroupSerializer(RLSSerializer, BaseWriteSerializer):
    providers = serializers.ResourceRelatedField(many=True, read_only=True)

    def validate(self, attrs):
        tenant = self.context["tenant_id"]
        name = attrs.get("name", self.instance.name if self.instance else None)

        # Exclude the current instance when checking for uniqueness during updates
        queryset = ProviderGroup.objects.filter(tenant=tenant, name=name)
        if self.instance:
            queryset = queryset.exclude(pk=self.instance.pk)

        if queryset.exists():
            raise serializers.ValidationError(
                {
                    "name": "A provider group with this name already exists for this tenant."
                }
            )

        return super().validate(attrs)

    class Meta:
        model = ProviderGroup
        fields = ["id", "name", "inserted_at", "updated_at", "providers", "url"]
        read_only_fields = ["id", "inserted_at", "updated_at"]
        extra_kwargs = {
            "id": {"read_only": True},
            "inserted_at": {"read_only": True},
            "updated_at": {"read_only": True},
        }


class ProviderGroupIncludedSerializer(RLSSerializer, BaseWriteSerializer):
    class Meta:
        model = ProviderGroup
        fields = ["id", "name"]


class ProviderGroupUpdateSerializer(RLSSerializer, BaseWriteSerializer):
    """
    Serializer for updating the ProviderGroup model.
    Only allows "name" field to be updated.
    """

    class Meta:
        model = ProviderGroup
        fields = ["id", "name"]


class ProviderGroupMembershipUpdateSerializer(RLSSerializer, BaseWriteSerializer):
    """
    Serializer for modifying provider group memberships
    """

    provider_ids = serializers.ListField(
        child=serializers.UUIDField(),
        help_text="List of provider UUIDs to add to the group",
    )

    def validate(self, attrs):
        tenant_id = self.context["tenant_id"]
        provider_ids = attrs.get("provider_ids", [])

        existing_provider_ids = set(
            Provider.objects.filter(
                id__in=provider_ids, tenant_id=tenant_id
            ).values_list("id", flat=True)
        )
        provided_provider_ids = set(provider_ids)

        missing_provider_ids = provided_provider_ids - existing_provider_ids

        if missing_provider_ids:
            raise serializers.ValidationError(
                {
                    "provider_ids": f"The following provider IDs do not exist: {', '.join(str(id) for id in missing_provider_ids)}"
                }
            )

        return super().validate(attrs)

    class Meta:
        model = ProviderGroupMembership
        fields = ["id", "provider_ids"]


# Providers
class ProviderEnumSerializerField(serializers.ChoiceField):
    def __init__(self, **kwargs):
        kwargs["choices"] = Provider.ProviderChoices.choices
        super().__init__(**kwargs)


class ProviderSerializer(RLSSerializer):
    """
    Serializer for the Provider model.
    """

    provider = ProviderEnumSerializerField()
    connection = serializers.SerializerMethodField(read_only=True)

    included_serializers = {
        "provider_groups": "api.v1.serializers.ProviderGroupIncludedSerializer",
    }

    class Meta:
        model = Provider
        fields = [
            "id",
            "inserted_at",
            "updated_at",
            "provider",
            "uid",
            "alias",
            "connection",
            # "scanner_args",
            "secret",
            "provider_groups",
            "url",
        ]

    @extend_schema_field(
        {
            "type": "object",
            "properties": {
                "connected": {"type": "boolean"},
                "last_checked_at": {"type": "string", "format": "date-time"},
            },
        }
    )
    def get_connection(self, obj):
        return {
            "connected": obj.connected,
            "last_checked_at": obj.connection_last_checked_at,
        }


class ProviderCreateSerializer(RLSSerializer, BaseWriteSerializer):
    class Meta:
        model = Provider
        fields = [
            "alias",
            "provider",
            "uid",
            # "scanner_args"
        ]


class ProviderUpdateSerializer(BaseWriteSerializer):
    """
    Serializer for updating the Provider model.
    Only allows "alias" and "scanner_args" fields to be updated.
    """

    class Meta:
        model = Provider
        fields = [
            "alias",
            # "scanner_args"
        ]


# Scans


class ScanTriggerEnumSerializerField(serializers.ChoiceField):
    def __init__(self, **kwargs):
        kwargs["choices"] = Scan.TriggerChoices.choices
        super().__init__(**kwargs)


class ScanSerializer(RLSSerializer):
    trigger = serializers.ChoiceField(
        choices=Scan.TriggerChoices.choices, read_only=True
    )
    state = StateEnumSerializerField(read_only=True)

    class Meta:
        model = Scan
        fields = [
            "id",
            "name",
            "trigger",
            "state",
            "unique_resource_count",
            "progress",
            # "scanner_args",
            "duration",
            "provider",
            "task",
            "inserted_at",
            "started_at",
            "completed_at",
            "scheduled_at",
            "next_scan_at",
            "url",
        ]


class ScanCreateSerializer(RLSSerializer, BaseWriteSerializer):
    class Meta:
        model = Scan
        # TODO: add mutelist when implemented
        fields = [
            "id",
            "provider",
            # "scanner_args",
            "name",
        ]

    def create(self, validated_data):
        # provider = validated_data.get("provider")

        # scanner_args will be disabled for the user in the first release
        # if not validated_data.get("scanner_args"):
        #     validated_data["scanner_args"] = provider.scanner_args
        # else:
        #     validated_data["scanner_args"] = merge_dicts(
        #         provider.scanner_args, validated_data["scanner_args"]
        #     )

        if not validated_data.get("trigger"):
            validated_data["trigger"] = Scan.TriggerChoices.MANUAL.value

        return RLSSerializer.create(self, validated_data)


class ScanUpdateSerializer(BaseWriteSerializer):
    """
    Serializer for updating the Provider model.
    Only allows "alias" and "scanner_args" fields to be updated.
    """

    class Meta:
        model = Scan
        # TODO: add mutelist when implemented
        fields = ["id", "name"]
        extra_kwargs = {
            "id": {"read_only": True},
        }


class ScanTaskSerializer(RLSSerializer):
    trigger = serializers.ChoiceField(
        choices=Scan.TriggerChoices.choices, read_only=True
    )
    state = StateEnumSerializerField(read_only=True)

    class Meta:
        model = Scan
        fields = [
            "id",
            "name",
            "trigger",
            "state",
            "unique_resource_count",
            "progress",
            # "scanner_args",
            "duration",
            "started_at",
            "completed_at",
            "scheduled_at",
        ]


class ResourceTagSerializer(RLSSerializer):
    """
    Serializer for the ResourceTag model
    """

    class Meta:
        model = ResourceTag
        fields = ["key", "value"]


class ResourceSerializer(RLSSerializer):
    """
    Serializer for the Resource model.
    """

    tags = serializers.SerializerMethodField()
    type_ = serializers.CharField(read_only=True)

    findings = serializers.ResourceRelatedField(many=True, read_only=True)

    class Meta:
        model = Resource
        fields = [
            "id",
            "inserted_at",
            "updated_at",
            "uid",
            "name",
            "region",
            "service",
            "type_",
            "tags",
            "provider",
            "findings",
            "url",
        ]
        extra_kwargs = {
            "id": {"read_only": True},
            "inserted_at": {"read_only": True},
            "updated_at": {"read_only": True},
        }

    included_serializers = {
        "findings": "api.v1.serializers.FindingSerializer",
        "provider": "api.v1.serializers.ProviderSerializer",
    }

    @extend_schema_field(
        {
            "type": "object",
            "description": "Tags associated with the resource",
            "example": {"env": "prod", "owner": "johndoe"},
        }
    )
    def get_tags(self, obj):
        return obj.get_tags()

    def get_fields(self):
        """`type` is a Python reserved keyword."""
        fields = super().get_fields()
        type_ = fields.pop("type_")
        fields["type"] = type_
        return fields


class FindingSerializer(RLSSerializer):
    """
    Serializer for the Finding model.
    """

    resources = serializers.ResourceRelatedField(many=True, read_only=True)

    class Meta:
        model = Finding
        fields = [
            "id",
            "uid",
            "delta",
            "status",
            "status_extended",
            "severity",
            "check_id",
            "check_metadata",
            "raw_result",
            "inserted_at",
            "updated_at",
            "url",
            # Relationships
            "scan",
            "resources",
        ]

    included_serializers = {
        "scan": ScanSerializer,
        "resources": ResourceSerializer,
    }


class FindingDynamicFilterSerializer(serializers.Serializer):
    services = serializers.ListField(child=serializers.CharField(), allow_empty=True)
    regions = serializers.ListField(child=serializers.CharField(), allow_empty=True)

    class Meta:
        resource_name = "finding-dynamic-filters"


# Provider secrets
class BaseWriteProviderSecretSerializer(BaseWriteSerializer):
    @staticmethod
    def validate_secret_based_on_provider(
        provider_type: str, secret_type: ProviderSecret.TypeChoices, secret: dict
    ):
        if secret_type == ProviderSecret.TypeChoices.STATIC:
            if provider_type == Provider.ProviderChoices.AWS.value:
                serializer = AwsProviderSecret(data=secret)
            elif provider_type == Provider.ProviderChoices.AZURE.value:
                serializer = AzureProviderSecret(data=secret)
            elif provider_type == Provider.ProviderChoices.GCP.value:
                serializer = GCPProviderSecret(data=secret)
            elif provider_type == Provider.ProviderChoices.KUBERNETES.value:
                serializer = KubernetesProviderSecret(data=secret)
            else:
                raise serializers.ValidationError(
                    {"provider": f"Provider type not supported {provider_type}"}
                )
        elif secret_type == ProviderSecret.TypeChoices.ROLE:
            serializer = AWSRoleAssumptionProviderSecret(data=secret)
        else:
            raise serializers.ValidationError(
                {"secret_type": f"Secret type not supported: {secret_type}"}
            )
        try:
            serializer.is_valid(raise_exception=True)
        except ValidationError as validation_error:
            # Customize the error message
            details = validation_error.detail.copy()
            for key, value in details.items():
                validation_error.detail[f"secret/{key}"] = value
                del validation_error.detail[key]
            raise validation_error


class AwsProviderSecret(serializers.Serializer):
    aws_access_key_id = serializers.CharField()
    aws_secret_access_key = serializers.CharField()
    aws_session_token = serializers.CharField(required=False)

    class Meta:
        resource_name = "provider-secrets"


class AzureProviderSecret(serializers.Serializer):
    client_id = serializers.CharField()
    client_secret = serializers.CharField()
    tenant_id = serializers.CharField()

    class Meta:
        resource_name = "provider-secrets"


class GCPProviderSecret(serializers.Serializer):
    client_id = serializers.CharField()
    client_secret = serializers.CharField()
    refresh_token = serializers.CharField()

    class Meta:
        resource_name = "provider-secrets"


class KubernetesProviderSecret(serializers.Serializer):
    kubeconfig_content = serializers.CharField()

    class Meta:
        resource_name = "provider-secrets"


class AWSRoleAssumptionProviderSecret(serializers.Serializer):
    role_arn = serializers.CharField()
    external_id = serializers.CharField(required=False)
    role_session_name = serializers.CharField(required=False)
    session_duration = serializers.IntegerField(
        required=False, min_value=900, max_value=43200
    )
    aws_access_key_id = serializers.CharField(required=False)
    aws_secret_access_key = serializers.CharField(required=False)
    aws_session_token = serializers.CharField(required=False)

    class Meta:
        resource_name = "provider-secrets"


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
                    "external_id": {
                        "type": "string",
                        "description": "An optional identifier to enhance security for role assumption; may be "
                        "required by the role administrator.",
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
                "required": ["role_arn"],
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
                "title": "Kubernetes Static Credentials",
                "properties": {
                    "kubeconfig_content": {
                        "type": "string",
                        "description": "The content of the Kubernetes kubeconfig file, encoded as a string.",
                    }
                },
                "required": ["kubeconfig_content"],
            },
        ]
    }
)
class ProviderSecretField(serializers.JSONField):
    pass


class ProviderSecretSerializer(RLSSerializer):
    """
    Serializer for the ProviderSecret model.
    """

    class Meta:
        model = ProviderSecret
        fields = [
            "id",
            "inserted_at",
            "updated_at",
            "name",
            "secret_type",
            "provider",
            "url",
        ]


class ProviderSecretCreateSerializer(RLSSerializer, BaseWriteProviderSecretSerializer):
    secret = ProviderSecretField(write_only=True)

    class Meta:
        model = ProviderSecret
        fields = [
            "inserted_at",
            "updated_at",
            "name",
            "secret_type",
            "secret",
            "provider",
        ]
        extra_kwargs = {
            "inserted_at": {"read_only": True},
            "updated_at": {"read_only": True},
        }

    def validate(self, attrs):
        provider = attrs.get("provider")
        secret_type = attrs.get("secret_type")
        secret = attrs.get("secret")

        validated_attrs = super().validate(attrs)
        self.validate_secret_based_on_provider(provider.provider, secret_type, secret)
        return validated_attrs


class ProviderSecretUpdateSerializer(BaseWriteProviderSecretSerializer):
    secret = ProviderSecretField(write_only=True)

    class Meta:
        model = ProviderSecret
        fields = [
            "id",
            "inserted_at",
            "updated_at",
            "name",
            "secret_type",
            "secret",
            "provider",
        ]
        extra_kwargs = {
            "inserted_at": {"read_only": True},
            "updated_at": {"read_only": True},
            "provider": {"read_only": True},
            "secret_type": {"read_only": True},
        }

    def validate(self, attrs):
        provider = self.instance.provider
        secret_type = self.instance.secret_type
        secret = attrs.get("secret")

        validated_attrs = super().validate(attrs)
        self.validate_secret_based_on_provider(provider.provider, secret_type, secret)
        return validated_attrs


# Invitations


class InvitationSerializer(RLSSerializer):
    """
    Serializer for the Invitation model.
    """

    class Meta:
        model = Invitation
        fields = [
            "id",
            "inserted_at",
            "updated_at",
            "email",
            "state",
            "token",
            "expires_at",
            "inviter",
            "url",
        ]


class InvitationBaseWriteSerializer(BaseWriteSerializer):
    def validate_email(self, value):
        user = User.objects.filter(email=value).first()
        tenant_id = self.context["tenant_id"]
        if user and Membership.objects.filter(user=user, tenant=tenant_id).exists():
            raise ValidationError(
                "The user may already be a member of the tenant or there was an issue with the "
                "email provided."
            )
        if Invitation.objects.filter(
            email=value, state=Invitation.State.PENDING
        ).exists():
            raise ValidationError(
                "Unable to process your request. Please check the information provided and "
                "try again."
            )
        return value

    def validate_expires_at(self, value):
        now = datetime.now(timezone.utc)
        if value and value < now + timedelta(hours=24):
            raise ValidationError(
                "Expiry date must be at least 24 hours in the future."
            )
        return value


class InvitationCreateSerializer(InvitationBaseWriteSerializer, RLSSerializer):
    expires_at = serializers.DateTimeField(
        required=False,
        help_text="UTC. Default 7 days. If this attribute is "
        "provided, it must be at least 24 hours in the "
        "future.",
    )

    class Meta:
        model = Invitation
        fields = ["email", "expires_at", "state", "token", "inviter"]
        extra_kwargs = {
            "token": {"read_only": True},
            "state": {"read_only": True},
            "inviter": {"read_only": True},
            "expires_at": {"required": False},
        }

    def create(self, validated_data):
        inviter = self.context.get("request").user
        validated_data["inviter"] = inviter
        return super().create(validated_data)


class InvitationUpdateSerializer(InvitationBaseWriteSerializer):
    class Meta:
        model = Invitation
        fields = ["id", "email", "expires_at", "state", "token"]
        extra_kwargs = {
            "token": {"read_only": True},
            "state": {"read_only": True},
            "expires_at": {"required": False},
            "email": {"required": False},
        }


class InvitationAcceptSerializer(RLSSerializer):
    """Serializer for accepting an invitation."""

    invitation_token = serializers.CharField(write_only=True)

    class Meta:
        model = Invitation
        fields = ["invitation_token"]


# Compliance overview


class ComplianceOverviewSerializer(RLSSerializer):
    """
    Serializer for the ComplianceOverview model.
    """

    requirements_status = serializers.SerializerMethodField(
        read_only=True, method_name="get_requirements_status"
    )
    provider_type = serializers.SerializerMethodField(read_only=True)

    class Meta:
        model = ComplianceOverview
        fields = [
            "id",
            "inserted_at",
            "compliance_id",
            "framework",
            "version",
            "requirements_status",
            "region",
            "provider_type",
            "scan",
            "url",
        ]

    @extend_schema_field(
        {
            "type": "object",
            "properties": {
                "passed": {"type": "integer"},
                "failed": {"type": "integer"},
                "manual": {"type": "integer"},
                "total": {"type": "integer"},
            },
        }
    )
    def get_requirements_status(self, obj):
        return {
            "passed": obj.requirements_passed,
            "failed": obj.requirements_failed,
            "manual": obj.requirements_manual,
            "total": obj.total_requirements,
        }

    @extend_schema_field(serializers.CharField(allow_null=True))
    def get_provider_type(self, obj):
        """
        Retrieves the provider_type from scan.provider.provider_type.
        """
        try:
            return obj.scan.provider.provider
        except AttributeError:
            return None


class ComplianceOverviewFullSerializer(ComplianceOverviewSerializer):
    requirements = serializers.SerializerMethodField(read_only=True)

    class Meta(ComplianceOverviewSerializer.Meta):
        fields = ComplianceOverviewSerializer.Meta.fields + [
            "description",
            "requirements",
        ]

    @extend_schema_field(
        {
            "type": "object",
            "properties": {
                "requirement_id": {
                    "type": "object",
                    "properties": {
                        "name": {"type": "string"},
                        "checks": {
                            "type": "object",
                            "properties": {
                                "check_name": {
                                    "type": "object",
                                    "properties": {
                                        "status": {
                                            "type": "string",
                                            "enum": ["PASS", "FAIL", None],
                                        },
                                    },
                                }
                            },
                            "description": "Each key in the 'checks' object is a check name, with values as "
                            "'PASS', 'FAIL', or null.",
                        },
                        "status": {
                            "type": "string",
                            "enum": ["PASS", "FAIL", "MANUAL"],
                        },
                        "attributes": {
                            "type": "array",
                            "items": {
                                "type": "object",
                            },
                        },
                        "description": {"type": "string"},
                        "checks_status": {
                            "type": "object",
                            "properties": {
                                "total": {"type": "integer"},
                                "pass": {"type": "integer"},
                                "fail": {"type": "integer"},
                                "manual": {"type": "integer"},
                            },
                        },
                    },
                }
            },
        }
    )
    def get_requirements(self, obj):
        """
        Returns the detailed structure of requirements.
        """
        return obj.requirements


# Overviews


class OverviewProviderSerializer(serializers.Serializer):
    id = serializers.CharField(source="provider")
    findings = serializers.SerializerMethodField(read_only=True)
    resources = serializers.SerializerMethodField(read_only=True)

    class JSONAPIMeta:
        resource_name = "providers-overview"

    def get_root_meta(self, _resource, _many):
        return {"version": "v1"}

    @extend_schema_field(
        {
            "type": "object",
            "properties": {
                "pass": {"type": "integer"},
                "fail": {"type": "integer"},
                "manual": {"type": "integer"},
                "total": {"type": "integer"},
            },
        }
    )
    def get_findings(self, obj):
        return {
            "pass": obj["findings_passed"],
            "fail": obj["findings_failed"],
            "manual": obj["findings_manual"],
            "total": obj["total_findings"],
        }

    @extend_schema_field(
        {
            "type": "object",
            "properties": {
                "total": {"type": "integer"},
            },
        }
    )
    def get_resources(self, obj):
        return {
            "total": obj["total_resources"],
        }


class OverviewFindingSerializer(serializers.Serializer):
    id = serializers.CharField(default="n/a")
    new = serializers.IntegerField()
    changed = serializers.IntegerField()
    unchanged = serializers.IntegerField()
    fail_new = serializers.IntegerField()
    fail_changed = serializers.IntegerField()
    pass_new = serializers.IntegerField()
    pass_changed = serializers.IntegerField()
    muted_new = serializers.IntegerField()
    muted_changed = serializers.IntegerField()
    total = serializers.IntegerField()
    _pass = serializers.IntegerField()
    fail = serializers.IntegerField()
    muted = serializers.IntegerField()

    class JSONAPIMeta:
        resource_name = "findings-overview"

    def get_root_meta(self, _resource, _many):
        return {"version": "v1"}

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["pass"] = self.fields.pop("_pass")


class OverviewSeveritySerializer(serializers.Serializer):
    id = serializers.CharField(default="n/a")
    critical = serializers.IntegerField()
    high = serializers.IntegerField()
    medium = serializers.IntegerField()
    low = serializers.IntegerField()
    informational = serializers.IntegerField()

    class JSONAPIMeta:
        resource_name = "findings-severity-overview"

    def get_root_meta(self, _resource, _many):
        return {"version": "v1"}


# Schedules


class ScheduleDailyCreateSerializer(serializers.Serializer):
    provider_id = serializers.UUIDField(required=True)

    class JSONAPIMeta:
        resource_name = "daily-schedules"

    # TODO: DRY this when we have more time
    def validate(self, data):
        if hasattr(self, "initial_data"):
            initial_data = set(self.initial_data.keys()) - {"id", "type"}
            unknown_keys = initial_data - set(self.fields.keys())
            if unknown_keys:
                raise ValidationError(f"Invalid fields: {unknown_keys}")
        return data
