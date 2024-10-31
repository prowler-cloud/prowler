import json

from django.conf import settings
from django.contrib.auth import authenticate
from django.contrib.auth.models import update_last_login
from django.contrib.auth.password_validation import validate_password
from drf_spectacular.utils import extend_schema_field
from jwt.exceptions import InvalidKeyError
from rest_framework_json_api import serializers
from rest_framework_json_api.serializers import ValidationError
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer

from api.models import (
    StateChoices,
    User,
    Membership,
    Provider,
    Scan,
    Task,
    Resource,
    ResourceTag,
    Finding,
    ProviderSecret,
)
from api.rls import Tenant
from api.utils import merge_dicts


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
        resource_name = "Token"

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

        # Set the nbf (not before) claim to the iat (issued at) claim. At this moment, simplejwt does not provide a way to set the nbf claim
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
        resource_name = "TokenRefresh"

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
            "scanner_args",
            "secret",
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
        fields = ["alias", "provider", "uid", "scanner_args"]


class ProviderUpdateSerializer(BaseWriteSerializer):
    """
    Serializer for updating the Provider model.
    Only allows "alias" and "scanner_args" fields to be updated.
    """

    class Meta:
        model = Provider
        fields = ["alias", "scanner_args"]


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
            "scanner_args",
            "duration",
            "provider",
            "task",
            "started_at",
            "completed_at",
            "scheduled_at",
            "url",
        ]


class ScanCreateSerializer(RLSSerializer, BaseWriteSerializer):
    class Meta:
        model = Scan
        # TODO: add mutelist when implemented
        fields = ["id", "provider", "scanner_args", "name"]

    def create(self, validated_data):
        provider = validated_data.get("provider")

        if not validated_data.get("scanner_args"):
            validated_data["scanner_args"] = provider.scanner_args
        else:
            validated_data["scanner_args"] = merge_dicts(
                provider.scanner_args, validated_data["scanner_args"]
            )

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
            "scanner_args",
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
        resource_name = "ProviderSecret"


class AzureProviderSecret(serializers.Serializer):
    client_id = serializers.CharField()
    client_secret = serializers.CharField()
    tenant_id = serializers.CharField()

    class Meta:
        resource_name = "ProviderSecret"


class GCPProviderSecret(serializers.Serializer):
    client_id = serializers.CharField()
    client_secret = serializers.CharField()
    refresh_token = serializers.CharField()

    class Meta:
        resource_name = "ProviderSecret"


class KubernetesProviderSecret(serializers.Serializer):
    kubeconfig_content = serializers.CharField()

    class Meta:
        resource_name = "ProviderSecret"


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
        resource_name = "ProviderSecret"


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
                        "description": "An identifier for the role session, useful for tracking sessions in AWS logs.",
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
