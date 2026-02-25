import base64
import json
from datetime import datetime, timedelta, timezone

from django.conf import settings
from django.contrib.auth import authenticate
from django.contrib.auth.models import update_last_login
from django.contrib.auth.password_validation import validate_password
from django.db import IntegrityError
from drf_spectacular.utils import extend_schema_field
from jwt.exceptions import InvalidKeyError
from rest_framework.reverse import reverse
from rest_framework.validators import UniqueTogetherValidator
from rest_framework_json_api import serializers
from rest_framework_json_api.relations import SerializerMethodResourceRelatedField
from rest_framework_json_api.serializers import ValidationError
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework_simplejwt.tokens import RefreshToken

from api.db_router import MainRouter
from api.exceptions import ConflictException
from api.models import (
    AttackPathsScan,
    Finding,
    Integration,
    IntegrationProviderRelationship,
    Invitation,
    InvitationRoleRelationship,
    LighthouseConfiguration,
    LighthouseProviderConfiguration,
    LighthouseProviderModels,
    LighthouseTenantConfiguration,
    Membership,
    MuteRule,
    Processor,
    Provider,
    ProviderGroup,
    ProviderGroupMembership,
    ProviderSecret,
    Resource,
    ResourceTag,
    Role,
    RoleProviderGroupRelationship,
    SAMLConfiguration,
    Scan,
    StateChoices,
    StatusChoices,
    Task,
    TenantAPIKey,
    ThreatScoreSnapshot,
    User,
    UserRoleRelationship,
)
from api.rls import Tenant
from api.v1.serializer_utils.integrations import (
    AWSCredentialSerializer,
    IntegrationConfigField,
    IntegrationCredentialField,
    JiraConfigSerializer,
    JiraCredentialSerializer,
    S3ConfigSerializer,
    SecurityHubConfigSerializer,
)
from api.v1.serializer_utils.lighthouse import (
    BedrockCredentialsSerializer,
    BedrockCredentialsUpdateSerializer,
    LighthouseCredentialsField,
    OpenAICompatibleCredentialsSerializer,
    OpenAICredentialsSerializer,
)
from api.v1.serializer_utils.processors import ProcessorConfigField
from api.v1.serializer_utils.providers import ProviderSecretField
from prowler.lib.mutelist.mutelist import Mutelist

# Base


class BaseModelSerializerV1(serializers.ModelSerializer):
    def get_root_meta(self, _resource, _many):
        return {"version": "v1"}


class BaseSerializerV1(serializers.Serializer):
    def get_root_meta(self, _resource, _many):
        return {"version": "v1"}


class BaseWriteSerializer(BaseModelSerializerV1):
    def validate(self, data):
        if hasattr(self, "initial_data"):
            initial_data = set(self.initial_data.keys()) - {"id", "type"}
            unknown_keys = initial_data - set(self.fields.keys())
            if unknown_keys:
                raise ValidationError(f"Invalid fields: {unknown_keys}")
        return data


class RLSSerializer(BaseModelSerializerV1):
    def create(self, validated_data):
        tenant_id = self.context.get("tenant_id")
        validated_data["tenant_id"] = tenant_id
        return super().create(validated_data)


class StateEnumSerializerField(serializers.ChoiceField):
    def __init__(self, **kwargs):
        kwargs["choices"] = StateChoices.choices
        super().__init__(**kwargs)


# Tokens


def generate_tokens(user: User, tenant_id: str) -> dict:
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


class BaseTokenSerializer(TokenObtainPairSerializer):
    def custom_validate(self, attrs, social: bool = False):
        email = attrs.get("email")
        password = attrs.get("password")
        tenant_id = str(attrs.get("tenant_id", ""))

        # Authenticate user
        user = (
            User.objects.get(email=email)
            if social
            else authenticate(username=email, password=password)
        )
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

        return generate_tokens(user, tenant_id)


class TokenSerializer(BaseTokenSerializer):
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
        return super().custom_validate(attrs)


class TokenSocialLoginSerializer(BaseTokenSerializer):
    email = serializers.EmailField(write_only=True)
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

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields.pop("password", None)

    def validate(self, attrs):
        return super().custom_validate(attrs, social=True)


# TODO: Check if we can change the parent class to TokenRefreshSerializer from rest_framework_simplejwt.serializers
class TokenRefreshSerializer(BaseSerializerV1):
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


class TokenSwitchTenantSerializer(BaseSerializerV1):
    tenant_id = serializers.UUIDField(
        write_only=True, help_text="The tenant ID for which to request a new token."
    )
    access = serializers.CharField(read_only=True)
    refresh = serializers.CharField(read_only=True)

    class JSONAPIMeta:
        resource_name = "tokens-switch-tenant"

    def validate(self, attrs):
        request = self.context["request"]
        user = request.user

        if not user.is_authenticated:
            raise ValidationError("Invalid or expired token.")

        tenant_id = str(attrs.get("tenant_id"))
        if not user.is_member_of_tenant(tenant_id):
            raise ValidationError("Tenant does not exist or user is not a member.")

        return generate_tokens(user, tenant_id)


# Users


class UserSerializer(BaseModelSerializerV1):
    """
    Serializer for the User model.
    """

    # We use SerializerMethodResourceRelatedField so includes (e.g. ?include=roles)
    # respect RBAC and do not leak relationships of other users when the requester
    # lacks manage_account. The visibility logic lives in get_roles/get_memberships.
    memberships = SerializerMethodResourceRelatedField(
        many=True, read_only=True, source="memberships", method_name="get_memberships"
    )
    roles = SerializerMethodResourceRelatedField(
        many=True, read_only=True, source="roles", method_name="get_roles"
    )

    class Meta:
        model = User
        fields = [
            "id",
            "name",
            "email",
            "company_name",
            "date_joined",
            "memberships",
            "roles",
        ]
        extra_kwargs = {
            "roles": {"read_only": True},
        }

    included_serializers = {
        "roles": "api.v1.serializers.RoleIncludeSerializer",
        "memberships": "api.v1.serializers.MembershipIncludeSerializer",
    }

    def _can_view_relationships(self, instance) -> bool:
        """Allow self to view own relationships. Require manage_account to view others."""
        role = self.context.get("role")
        request = self.context.get("request")
        is_self = bool(
            request
            and getattr(request, "user", None)
            and getattr(instance, "id", None) == request.user.id
        )
        return is_self or (role and role.manage_account)

    def get_roles(self, instance):
        return (
            instance.roles.all()
            if self._can_view_relationships(instance)
            else Role.objects.none()
        )

    def get_memberships(self, instance):
        return (
            instance.memberships.all()
            if self._can_view_relationships(instance)
            else Membership.objects.none()
        )


class UserIncludeSerializer(UserSerializer):
    class Meta:
        model = User
        fields = [
            "id",
            "name",
            "email",
            "company_name",
            "date_joined",
            "roles",
        ]

    included_serializers = {
        "roles": "api.v1.serializers.RoleIncludeSerializer",
    }


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


class RoleResourceIdentifierSerializer(BaseSerializerV1):
    resource_type = serializers.CharField(source="type")
    id = serializers.UUIDField()

    class JSONAPIMeta:
        resource_name = "role-identifier"

    def to_representation(self, instance):
        """
        Ensure 'type' is used in the output instead of 'resource_type'.
        """
        representation = super().to_representation(instance)
        representation["type"] = representation.pop("resource_type", None)
        return representation

    def to_internal_value(self, data):
        """
        Map 'type' back to 'resource_type' during input.
        """
        data["resource_type"] = data.pop("type", None)
        return super().to_internal_value(data)


class UserRoleRelationshipSerializer(RLSSerializer, BaseWriteSerializer):
    """
    Serializer for modifying user memberships
    """

    roles = serializers.ListField(
        child=RoleResourceIdentifierSerializer(),
        help_text="List of resource identifier objects representing roles.",
    )

    def create(self, validated_data):
        role_ids = [item["id"] for item in validated_data["roles"]]
        roles = Role.objects.filter(id__in=role_ids)
        tenant_id = self.context.get("tenant_id")

        new_relationships = [
            UserRoleRelationship(
                user=self.context.get("user"), role=r, tenant_id=tenant_id
            )
            for r in roles
        ]
        UserRoleRelationship.objects.bulk_create(new_relationships)

        return self.context.get("user")

    def update(self, instance, validated_data):
        role_ids = [item["id"] for item in validated_data["roles"]]
        roles = Role.objects.filter(id__in=role_ids)
        tenant_id = self.context.get("tenant_id")

        # Safeguard: A tenant must always have at least one user with MANAGE_ACCOUNT.
        # If the target roles do NOT include MANAGE_ACCOUNT, and the current user is
        # the only one in the tenant with MANAGE_ACCOUNT, block the update.
        target_includes_manage_account = roles.filter(manage_account=True).exists()
        if not target_includes_manage_account:
            # Check if any other user has MANAGE_ACCOUNT
            other_users_have_manage_account = (
                UserRoleRelationship.objects.filter(
                    tenant_id=tenant_id, role__manage_account=True
                )
                .exclude(user_id=instance.id)
                .exists()
            )

            # Check if the current user has MANAGE_ACCOUNT
            instance_has_manage_account = instance.roles.filter(
                tenant_id=tenant_id, manage_account=True
            ).exists()

            # If the current user is the last holder of MANAGE_ACCOUNT, prevent removal
            if instance_has_manage_account and not other_users_have_manage_account:
                raise serializers.ValidationError(
                    {
                        "roles": "At least one user in the tenant must retain MANAGE_ACCOUNT. "
                        "Assign MANAGE_ACCOUNT to another user before removing it here."
                    }
                )

        instance.roles.clear()
        new_relationships = [
            UserRoleRelationship(user=instance, role=r, tenant_id=tenant_id)
            for r in roles
        ]
        UserRoleRelationship.objects.bulk_create(new_relationships)

        return instance

    class Meta:
        model = UserRoleRelationship
        fields = ["id", "roles"]


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


class TenantSerializer(BaseModelSerializerV1):
    """
    Serializer for the Tenant model.
    """

    memberships = serializers.ResourceRelatedField(many=True, read_only=True)

    class Meta:
        model = Tenant
        fields = ["id", "name", "memberships"]


class TenantIncludeSerializer(BaseModelSerializerV1):
    class Meta:
        model = Tenant
        fields = ["id", "name"]


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


class MembershipIncludeSerializer(serializers.ModelSerializer):
    """
    Include-oriented Membership serializer that enables including tenant objects with names
    without altering the base MembershipSerializer behavior.
    """

    role = MemberRoleEnumSerializerField()
    user = serializers.ResourceRelatedField(read_only=True)
    tenant = SerializerMethodResourceRelatedField(read_only=True, source="tenant")

    class Meta:
        model = Membership
        fields = ["id", "user", "tenant", "role", "date_joined"]

    included_serializers = {"tenant": "api.v1.serializers.TenantIncludeSerializer"}

    def get_tenant(self, instance):
        try:
            return Tenant.objects.using(MainRouter.admin_db).get(id=instance.tenant_id)
        except Tenant.DoesNotExist:
            return None


# Provider Groups
class ProviderGroupSerializer(RLSSerializer, BaseWriteSerializer):
    providers = serializers.ResourceRelatedField(
        queryset=Provider.objects.all(), many=True, required=False
    )
    roles = serializers.ResourceRelatedField(
        queryset=Role.objects.all(), many=True, required=False
    )

    def validate(self, attrs):
        if ProviderGroup.objects.filter(name=attrs.get("name")).exists():
            raise serializers.ValidationError(
                {"name": "A provider group with this name already exists."}
            )

        return super().validate(attrs)

    class Meta:
        model = ProviderGroup
        fields = [
            "id",
            "name",
            "inserted_at",
            "updated_at",
            "providers",
            "roles",
            "url",
        ]
        extra_kwargs = {
            "id": {"read_only": True},
            "inserted_at": {"read_only": True},
            "updated_at": {"read_only": True},
            "roles": {"read_only": True},
            "url": {"read_only": True},
        }


class ProviderGroupIncludedSerializer(ProviderGroupSerializer):
    class Meta:
        model = ProviderGroup
        fields = ["id", "name"]


class ProviderGroupCreateSerializer(ProviderGroupSerializer):
    providers = serializers.ResourceRelatedField(
        queryset=Provider.objects.all(), many=True, required=False
    )
    roles = serializers.ResourceRelatedField(
        queryset=Role.objects.all(), many=True, required=False
    )

    class Meta:
        model = ProviderGroup
        fields = [
            "id",
            "name",
            "inserted_at",
            "updated_at",
            "providers",
            "roles",
        ]

    def create(self, validated_data):
        providers = validated_data.pop("providers", [])
        roles = validated_data.pop("roles", [])
        tenant_id = self.context.get("tenant_id")
        provider_group = ProviderGroup.objects.create(
            tenant_id=tenant_id, **validated_data
        )

        through_model_instances = [
            ProviderGroupMembership(
                provider_group=provider_group,
                provider=provider,
                tenant_id=tenant_id,
            )
            for provider in providers
        ]
        ProviderGroupMembership.objects.bulk_create(through_model_instances)

        through_model_instances = [
            RoleProviderGroupRelationship(
                provider_group=provider_group,
                role=role,
                tenant_id=tenant_id,
            )
            for role in roles
        ]
        RoleProviderGroupRelationship.objects.bulk_create(through_model_instances)

        return provider_group


class ProviderGroupUpdateSerializer(ProviderGroupSerializer):
    def update(self, instance, validated_data):
        tenant_id = self.context.get("tenant_id")

        if "providers" in validated_data:
            providers = validated_data.pop("providers")
            instance.providers.clear()
            through_model_instances = [
                ProviderGroupMembership(
                    provider_group=instance,
                    provider=provider,
                    tenant_id=tenant_id,
                )
                for provider in providers
            ]
            ProviderGroupMembership.objects.bulk_create(through_model_instances)

        if "roles" in validated_data:
            roles = validated_data.pop("roles")
            instance.roles.clear()
            through_model_instances = [
                RoleProviderGroupRelationship(
                    provider_group=instance,
                    role=role,
                    tenant_id=tenant_id,
                )
                for role in roles
            ]
            RoleProviderGroupRelationship.objects.bulk_create(through_model_instances)

        return super().update(instance, validated_data)


class ProviderResourceIdentifierSerializer(BaseSerializerV1):
    resource_type = serializers.CharField(source="type")
    id = serializers.UUIDField()

    class JSONAPIMeta:
        resource_name = "provider-identifier"

    def to_representation(self, instance):
        """
        Ensure 'type' is used in the output instead of 'resource_type'.
        """
        representation = super().to_representation(instance)
        representation["type"] = representation.pop("resource_type", None)
        return representation

    def to_internal_value(self, data):
        """
        Map 'type' back to 'resource_type' during input.
        """
        data["resource_type"] = data.pop("type", None)
        return super().to_internal_value(data)


class ProviderGroupMembershipSerializer(RLSSerializer, BaseWriteSerializer):
    """
    Serializer for modifying provider_group memberships
    """

    providers = serializers.ListField(
        child=ProviderResourceIdentifierSerializer(),
        help_text="List of resource identifier objects representing providers.",
    )

    def create(self, validated_data):
        provider_ids = [item["id"] for item in validated_data["providers"]]
        providers = Provider.objects.filter(id__in=provider_ids)
        tenant_id = self.context.get("tenant_id")

        new_relationships = [
            ProviderGroupMembership(
                provider_group=self.context.get("provider_group"),
                provider=p,
                tenant_id=tenant_id,
            )
            for p in providers
        ]
        ProviderGroupMembership.objects.bulk_create(new_relationships)

        return self.context.get("provider_group")

    def update(self, instance, validated_data):
        provider_ids = [item["id"] for item in validated_data["providers"]]
        providers = Provider.objects.filter(id__in=provider_ids)
        tenant_id = self.context.get("tenant_id")

        instance.providers.clear()
        new_relationships = [
            ProviderGroupMembership(
                provider_group=instance, provider=p, tenant_id=tenant_id
            )
            for p in providers
        ]
        ProviderGroupMembership.objects.bulk_create(new_relationships)

        return instance

    class Meta:
        model = ProviderGroupMembership
        fields = ["id", "providers"]


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


class ProviderIncludeSerializer(RLSSerializer):
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
            # "scanner_args",
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
        extra_kwargs = {
            "alias": {
                "help_text": "Human readable name to identify the provider, e.g. 'Production AWS Account', 'Dev Environment'",
            },
            "provider": {
                "help_text": "Type of provider to create.",
            },
            "uid": {
                "help_text": "Unique identifier for the provider, set by the provider, e.g. AWS account ID, Azure subscription ID, GCP project ID, etc.",
            },
        }


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
        extra_kwargs = {
            "alias": {
                "help_text": "Human readable name to identify the provider, e.g. 'Production AWS Account', 'Dev Environment'",
            }
        }


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
            "processor",
            "url",
        ]

    included_serializers = {
        "provider": "api.v1.serializers.ProviderIncludeSerializer",
    }


class ScanIncludeSerializer(RLSSerializer):
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
            "inserted_at",
            "started_at",
            "completed_at",
            "scheduled_at",
            "provider",
        ]

    included_serializers = {
        "provider": "api.v1.serializers.ProviderIncludeSerializer",
    }


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


class ScanReportSerializer(BaseSerializerV1):
    id = serializers.CharField(source="scan")

    class Meta:
        resource_name = "scan-reports"
        fields = ["id"]


class ScanComplianceReportSerializer(BaseSerializerV1):
    id = serializers.CharField(source="scan")
    name = serializers.CharField()

    class Meta:
        resource_name = "scan-reports"
        fields = ["id", "name"]


class AttackPathsScanSerializer(RLSSerializer):
    state = StateEnumSerializerField(read_only=True)
    provider_alias = serializers.SerializerMethodField(read_only=True)
    provider_type = serializers.SerializerMethodField(read_only=True)
    provider_uid = serializers.SerializerMethodField(read_only=True)

    class Meta:
        model = AttackPathsScan
        fields = [
            "id",
            "state",
            "progress",
            "graph_data_ready",
            "provider",
            "provider_alias",
            "provider_type",
            "provider_uid",
            "scan",
            "task",
            "inserted_at",
            "started_at",
            "completed_at",
            "duration",
        ]

    included_serializers = {
        "provider": "api.v1.serializers.ProviderIncludeSerializer",
        "scan": "api.v1.serializers.ScanIncludeSerializer",
        "task": "api.v1.serializers.TaskSerializer",
    }

    def get_provider_alias(self, obj):
        provider = getattr(obj, "provider", None)
        return provider.alias if provider else None

    def get_provider_type(self, obj):
        provider = getattr(obj, "provider", None)
        return provider.provider if provider else None

    def get_provider_uid(self, obj):
        provider = getattr(obj, "provider", None)
        return provider.uid if provider else None


class AttackPathsQueryAttributionSerializer(BaseSerializerV1):
    text = serializers.CharField()
    link = serializers.CharField()

    class JSONAPIMeta:
        resource_name = "attack-paths-query-attributions"


class AttackPathsQueryParameterSerializer(BaseSerializerV1):
    name = serializers.CharField()
    label = serializers.CharField()
    data_type = serializers.CharField(default="string")
    description = serializers.CharField(allow_null=True, required=False)
    placeholder = serializers.CharField(allow_null=True, required=False)

    class JSONAPIMeta:
        resource_name = "attack-paths-query-parameters"


class AttackPathsQuerySerializer(BaseSerializerV1):
    id = serializers.CharField()
    name = serializers.CharField()
    short_description = serializers.CharField()
    description = serializers.CharField()
    attribution = AttackPathsQueryAttributionSerializer(allow_null=True, required=False)
    provider = serializers.CharField()
    parameters = AttackPathsQueryParameterSerializer(many=True)

    class JSONAPIMeta:
        resource_name = "attack-paths-queries"


class AttackPathsQueryRunRequestSerializer(BaseSerializerV1):
    id = serializers.CharField()
    parameters = serializers.DictField(
        child=serializers.JSONField(), allow_empty=True, required=False
    )

    class JSONAPIMeta:
        resource_name = "attack-paths-query-run-requests"


class AttackPathsCustomQueryRunRequestSerializer(BaseSerializerV1):
    cypher = serializers.CharField()

    class JSONAPIMeta:
        resource_name = "attack-paths-custom-query-run-requests"


class AttackPathsNodeSerializer(BaseSerializerV1):
    id = serializers.CharField()
    labels = serializers.ListField(child=serializers.CharField())
    properties = serializers.DictField(child=serializers.JSONField())

    class JSONAPIMeta:
        resource_name = "attack-paths-query-result-nodes"


class AttackPathsRelationshipSerializer(BaseSerializerV1):
    id = serializers.CharField()
    label = serializers.CharField()
    source = serializers.CharField()
    target = serializers.CharField()
    properties = serializers.DictField(child=serializers.JSONField())

    class JSONAPIMeta:
        resource_name = "attack-paths-query-result-relationships"


class AttackPathsQueryResultSerializer(BaseSerializerV1):
    nodes = AttackPathsNodeSerializer(many=True)
    relationships = AttackPathsRelationshipSerializer(many=True)
    total_nodes = serializers.IntegerField()
    truncated = serializers.BooleanField()

    class JSONAPIMeta:
        resource_name = "attack-paths-query-results"


class AttackPathsCartographySchemaSerializer(BaseSerializerV1):
    id = serializers.CharField()
    provider = serializers.CharField()
    cartography_version = serializers.CharField()
    schema_url = serializers.URLField()
    raw_schema_url = serializers.URLField()

    class JSONAPIMeta:
        resource_name = "attack-paths-cartography-schemas"


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
    failed_findings_count = serializers.IntegerField(read_only=True)

    findings = SerializerMethodResourceRelatedField(
        many=True,
        read_only=True,
    )

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
            "failed_findings_count",
            "url",
            "metadata",
            "details",
            "partition",
            "groups",
        ]
        extra_kwargs = {
            "id": {"read_only": True},
            "inserted_at": {"read_only": True},
            "updated_at": {"read_only": True},
            "metadata": {"read_only": True},
            "details": {"read_only": True},
            "partition": {"read_only": True},
            "groups": {"read_only": True},
        }

    included_serializers = {
        "findings": "api.v1.serializers.FindingIncludeSerializer",
        "provider": "api.v1.serializers.ProviderIncludeSerializer",
    }

    @extend_schema_field(
        {
            "type": "object",
            "description": "Tags associated with the resource",
            "example": {"env": "prod", "owner": "johndoe"},
        }
    )
    def get_tags(self, obj):
        # Use prefetched tags if available to avoid N+1 queries
        if hasattr(obj, "prefetched_tags"):
            return {tag.key: tag.value for tag in obj.prefetched_tags}
        # Fallback to the original method if prefetch is not available
        return obj.get_tags(self.context.get("tenant_id"))

    def get_fields(self):
        """`type` is a Python reserved keyword."""
        fields = super().get_fields()
        type_ = fields.pop("type_")
        fields["type"] = type_
        return fields

    def get_findings(self, obj):
        return (
            obj.latest_findings
            if hasattr(obj, "latest_findings")
            else obj.findings.all()
        )


class ResourceIncludeSerializer(RLSSerializer):
    """
    Serializer for the included Resource model.
    """

    tags = serializers.SerializerMethodField()
    type_ = serializers.CharField(read_only=True)

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
            "details",
            "partition",
        ]
        extra_kwargs = {
            "id": {"read_only": True},
            "inserted_at": {"read_only": True},
            "updated_at": {"read_only": True},
            "details": {"read_only": True},
            "partition": {"read_only": True},
        }

    @extend_schema_field(
        {
            "type": "object",
            "description": "Tags associated with the resource",
            "example": {"env": "prod", "owner": "johndoe"},
        }
    )
    def get_tags(self, obj):
        # Use prefetched tags if available to avoid N+1 queries
        if hasattr(obj, "prefetched_tags"):
            return {tag.key: tag.value for tag in obj.prefetched_tags}
        # Fallback to the original method if prefetch is not available
        return obj.get_tags(self.context.get("tenant_id"))

    def get_fields(self):
        """`type` is a Python reserved keyword."""
        fields = super().get_fields()
        type_ = fields.pop("type_")
        fields["type"] = type_
        return fields


class ResourceMetadataSerializer(BaseSerializerV1):
    services = serializers.ListField(child=serializers.CharField(), allow_empty=True)
    regions = serializers.ListField(child=serializers.CharField(), allow_empty=True)
    types = serializers.ListField(child=serializers.CharField(), allow_empty=True)
    groups = serializers.ListField(child=serializers.CharField(), allow_empty=True)
    # Temporarily disabled until we implement tag filtering in the UI
    # tags = serializers.JSONField(help_text="Tags are described as key-value pairs.")

    class Meta:
        resource_name = "resources-metadata"


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
            "categories",
            "resource_groups",
            "raw_result",
            "inserted_at",
            "updated_at",
            "first_seen_at",
            "muted",
            "muted_reason",
            "url",
            # Relationships
            "scan",
            "resources",
        ]

    included_serializers = {
        "scan": ScanIncludeSerializer,
        "resources": ResourceIncludeSerializer,
    }


class FindingIncludeSerializer(RLSSerializer):
    """
    Serializer for the include Finding model.
    """

    class Meta:
        model = Finding
        fields = [
            "id",
            "uid",
            "status",
            "severity",
            "check_id",
            "check_metadata",
            "inserted_at",
            "updated_at",
            "first_seen_at",
            "muted",
            "muted_reason",
        ]


# To be removed when the related endpoint is removed as well
class FindingDynamicFilterSerializer(BaseSerializerV1):
    services = serializers.ListField(child=serializers.CharField(), allow_empty=True)
    regions = serializers.ListField(child=serializers.CharField(), allow_empty=True)

    class Meta:
        resource_name = "finding-dynamic-filters"


class FindingMetadataSerializer(BaseSerializerV1):
    services = serializers.ListField(child=serializers.CharField(), allow_empty=True)
    regions = serializers.ListField(child=serializers.CharField(), allow_empty=True)
    resource_types = serializers.ListField(
        child=serializers.CharField(), allow_empty=True
    )
    categories = serializers.ListField(child=serializers.CharField(), allow_empty=True)
    groups = serializers.ListField(
        child=serializers.CharField(), allow_empty=True, required=False, default=list
    )
    # Temporarily disabled until we implement tag filtering in the UI
    # tags = serializers.JSONField(help_text="Tags are described as key-value pairs.")

    class Meta:
        resource_name = "findings-metadata"


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
            elif provider_type == Provider.ProviderChoices.GITHUB.value:
                serializer = GithubProviderSecret(data=secret)
            elif provider_type == Provider.ProviderChoices.IAC.value:
                serializer = IacProviderSecret(data=secret)
            elif provider_type == Provider.ProviderChoices.KUBERNETES.value:
                serializer = KubernetesProviderSecret(data=secret)
            elif provider_type == Provider.ProviderChoices.M365.value:
                serializer = M365ProviderSecret(data=secret)
            elif provider_type == Provider.ProviderChoices.ORACLECLOUD.value:
                serializer = OracleCloudProviderSecret(data=secret)
            elif provider_type == Provider.ProviderChoices.MONGODBATLAS.value:
                serializer = MongoDBAtlasProviderSecret(data=secret)
            elif provider_type == Provider.ProviderChoices.ALIBABACLOUD.value:
                serializer = AlibabaCloudProviderSecret(data=secret)
            elif provider_type == Provider.ProviderChoices.CLOUDFLARE.value:
                if "api_token" in secret:
                    serializer = CloudflareTokenProviderSecret(data=secret)
                elif "api_key" in secret and "api_email" in secret:
                    serializer = CloudflareApiKeyProviderSecret(data=secret)
                else:
                    raise serializers.ValidationError(
                        {
                            "secret": "Cloudflare credentials must include either 'api_token' "
                            "or both 'api_key' and 'api_email'."
                        }
                    )
            elif provider_type == Provider.ProviderChoices.OPENSTACK.value:
                serializer = OpenStackCloudsYamlProviderSecret(data=secret)
            elif provider_type == Provider.ProviderChoices.IMAGE.value:
                serializer = ImageProviderSecret(data=secret)
            else:
                raise serializers.ValidationError(
                    {"provider": f"Provider type not supported {provider_type}"}
                )
        elif secret_type == ProviderSecret.TypeChoices.ROLE:
            if provider_type == Provider.ProviderChoices.AWS.value:
                serializer = AWSRoleAssumptionProviderSecret(data=secret)
            elif provider_type == Provider.ProviderChoices.ALIBABACLOUD.value:
                serializer = AlibabaCloudRoleAssumptionProviderSecret(data=secret)
            else:
                raise serializers.ValidationError(
                    {
                        "secret_type": f"Role assumption not supported for provider type: {provider_type}"
                    }
                )
        elif secret_type == ProviderSecret.TypeChoices.SERVICE_ACCOUNT:
            serializer = GCPServiceAccountProviderSecret(data=secret)
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


class M365ProviderSecret(serializers.Serializer):
    client_id = serializers.CharField()
    client_secret = serializers.CharField(required=False)
    tenant_id = serializers.CharField()
    user = serializers.EmailField(required=False)
    password = serializers.CharField(required=False)
    certificate_content = serializers.CharField(required=False)

    def validate(self, attrs):
        if attrs.get("client_secret") and attrs.get("certificate_content"):
            raise serializers.ValidationError(
                "You cannot provide both client_secret and certificate_content."
            )
        if not attrs.get("client_secret") and not attrs.get("certificate_content"):
            raise serializers.ValidationError(
                "You must provide either client_secret or certificate_content."
            )
        return super().validate(attrs)

    def validate_certificate_content(self, certificate_content):
        """Validate that M365 certificate content is valid base64 encoded data."""
        if certificate_content:
            try:
                base64.b64decode(certificate_content, validate=True)
            except Exception as e:
                raise ValidationError(
                    {
                        "certificate_content": [
                            f"The provided certificate content is not valid base64 encoded data: {str(e)}"
                        ]
                    },
                    code="m365-certificate-content",
                )
        return certificate_content

    class Meta:
        resource_name = "provider-secrets"


class GCPProviderSecret(serializers.Serializer):
    client_id = serializers.CharField()
    client_secret = serializers.CharField()
    refresh_token = serializers.CharField()

    class Meta:
        resource_name = "provider-secrets"


class GCPServiceAccountProviderSecret(serializers.Serializer):
    service_account_key = serializers.JSONField()

    class Meta:
        resource_name = "provider-secrets"


class MongoDBAtlasProviderSecret(serializers.Serializer):
    atlas_public_key = serializers.CharField()
    atlas_private_key = serializers.CharField()

    class Meta:
        resource_name = "provider-secrets"


class KubernetesProviderSecret(serializers.Serializer):
    kubeconfig_content = serializers.CharField()

    class Meta:
        resource_name = "provider-secrets"


class GithubProviderSecret(serializers.Serializer):
    personal_access_token = serializers.CharField(required=False)
    oauth_app_token = serializers.CharField(required=False)
    github_app_id = serializers.IntegerField(required=False)
    github_app_key_content = serializers.CharField(required=False)

    class Meta:
        resource_name = "provider-secrets"


class IacProviderSecret(serializers.Serializer):
    repository_url = serializers.CharField()
    access_token = serializers.CharField(required=False)

    class Meta:
        resource_name = "provider-secrets"


class OracleCloudProviderSecret(serializers.Serializer):
    user = serializers.CharField()
    fingerprint = serializers.CharField()
    key_file = serializers.CharField(required=False)
    key_content = serializers.CharField(required=False)
    tenancy = serializers.CharField()
    region = serializers.CharField()
    pass_phrase = serializers.CharField(required=False)

    class Meta:
        resource_name = "provider-secrets"


class CloudflareTokenProviderSecret(serializers.Serializer):
    api_token = serializers.CharField()

    class Meta:
        resource_name = "provider-secrets"


class CloudflareApiKeyProviderSecret(serializers.Serializer):
    api_key = serializers.CharField()
    api_email = serializers.EmailField()

    class Meta:
        resource_name = "provider-secrets"


class OpenStackCloudsYamlProviderSecret(serializers.Serializer):
    clouds_yaml_content = serializers.CharField()
    clouds_yaml_cloud = serializers.CharField()

    class Meta:
        resource_name = "provider-secrets"


class ImageProviderSecret(serializers.Serializer):
    registry_username = serializers.CharField(required=False)
    registry_password = serializers.CharField(required=False)
    registry_token = serializers.CharField(required=False)

    class Meta:
        resource_name = "provider-secrets"

    def validate(self, attrs):
        token = attrs.get("registry_token")
        username = attrs.get("registry_username")
        password = attrs.get("registry_password")
        if not token:
            if username and not password:
                raise serializers.ValidationError(
                    "registry_password is required when registry_username is provided."
                )
            if password and not username:
                raise serializers.ValidationError(
                    "registry_username is required when registry_password is provided."
                )
        return attrs


class AlibabaCloudProviderSecret(serializers.Serializer):
    access_key_id = serializers.CharField()
    access_key_secret = serializers.CharField()
    security_token = serializers.CharField(required=False)

    class Meta:
        resource_name = "provider-secrets"


class AlibabaCloudRoleAssumptionProviderSecret(serializers.Serializer):
    role_arn = serializers.CharField(
        help_text="Access Key ID of the RAM user that will assume the role"
    )
    access_key_id = serializers.CharField(
        help_text="Access Key ID of the RAM user that will assume the role"
    )
    access_key_secret = serializers.CharField(
        help_text="Access Key Secret of the RAM user that will assume the role"
    )
    role_session_name = serializers.CharField(
        required=False,
        help_text="Session name for the assumed role session (optional, defaults to 'ProwlerSession')",
    )

    class Meta:
        resource_name = "provider-secrets"


class AWSRoleAssumptionProviderSecret(serializers.Serializer):
    role_arn = serializers.CharField()
    external_id = serializers.CharField()
    role_session_name = serializers.CharField(required=False)
    session_duration = serializers.IntegerField(
        required=False, min_value=900, max_value=43200
    )
    aws_access_key_id = serializers.CharField(required=False)
    aws_secret_access_key = serializers.CharField(required=False)
    aws_session_token = serializers.CharField(required=False)

    class Meta:
        resource_name = "provider-secrets"


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
            "secret_type": {"required": False},
        }

    def validate(self, attrs):
        provider = self.instance.provider
        # To allow updating a secret with the same type without making the `secret_type` mandatory
        secret_type = attrs.get("secret_type") or self.instance.secret_type
        secret = attrs.get("secret")

        validated_attrs = super().validate(attrs)
        self.validate_secret_based_on_provider(provider.provider, secret_type, secret)
        return validated_attrs


# Invitations


class InvitationSerializer(RLSSerializer):
    """
    Serializer for the Invitation model.
    """

    roles = serializers.ResourceRelatedField(many=True, queryset=Role.objects.all())

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        tenant_id = self.context.get("tenant_id")
        if tenant_id is not None:
            self.fields["roles"].queryset = Role.objects.filter(tenant_id=tenant_id)

    class Meta:
        model = Invitation
        fields = [
            "id",
            "inserted_at",
            "updated_at",
            "email",
            "state",
            "token",
            "roles",
            "expires_at",
            "inviter",
            "url",
        ]


class InvitationBaseWriteSerializer(BaseWriteSerializer):
    roles = serializers.ResourceRelatedField(many=True, queryset=Role.objects.all())

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        tenant_id = self.context.get("tenant_id")
        if tenant_id is not None:
            self.fields["roles"].queryset = Role.objects.filter(tenant_id=tenant_id)

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
        fields = ["email", "expires_at", "state", "token", "inviter", "roles"]
        extra_kwargs = {
            "token": {"read_only": True},
            "state": {"read_only": True},
            "inviter": {"read_only": True},
            "expires_at": {"required": False},
            "roles": {"required": False},
        }

    def create(self, validated_data):
        inviter = self.context.get("request").user
        tenant_id = self.context.get("tenant_id")
        validated_data["inviter"] = inviter
        roles = validated_data.pop("roles", [])
        invitation = super().create(validated_data)
        for role in roles:
            InvitationRoleRelationship.objects.create(
                role=role, invitation=invitation, tenant_id=tenant_id
            )

        return invitation


class InvitationUpdateSerializer(InvitationBaseWriteSerializer):
    roles = serializers.ResourceRelatedField(
        required=False, many=True, queryset=Role.objects.all()
    )

    class Meta:
        model = Invitation
        fields = ["id", "email", "expires_at", "state", "token", "roles"]
        extra_kwargs = {
            "token": {"read_only": True},
            "state": {"read_only": True},
            "expires_at": {"required": False},
            "email": {"required": False},
            "roles": {"required": False},
        }

    def update(self, instance, validated_data):
        tenant_id = self.context.get("tenant_id")
        if "roles" in validated_data:
            roles = validated_data.pop("roles")
            instance.roles.clear()
            new_relationships = [
                InvitationRoleRelationship(
                    role=r, invitation=instance, tenant_id=tenant_id
                )
                for r in roles
            ]
            InvitationRoleRelationship.objects.bulk_create(new_relationships)

        invitation = super().update(instance, validated_data)

        return invitation


class InvitationAcceptSerializer(RLSSerializer):
    """Serializer for accepting an invitation."""

    invitation_token = serializers.CharField(write_only=True)

    class Meta:
        model = Invitation
        fields = ["invitation_token"]


# Roles


class RoleSerializer(RLSSerializer, BaseWriteSerializer):
    permission_state = serializers.SerializerMethodField()
    users = serializers.ResourceRelatedField(
        queryset=User.objects.all(), many=True, required=False
    )
    provider_groups = serializers.ResourceRelatedField(
        queryset=ProviderGroup.objects.all(), many=True, required=False
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        tenant_id = self.context.get("tenant_id")
        if tenant_id is not None:
            self.fields["users"].queryset = User.objects.filter(
                membership__tenant__id=tenant_id
            )
            self.fields["provider_groups"].queryset = ProviderGroup.objects.filter(
                tenant_id=self.context.get("tenant_id")
            )

    def get_permission_state(self, obj) -> str:
        return obj.permission_state

    def validate(self, attrs):
        if Role.objects.filter(name=attrs.get("name")).exists():
            raise serializers.ValidationError(
                {"name": "A role with this name already exists."}
            )

        if attrs.get("manage_providers"):
            attrs["unlimited_visibility"] = True

        # Prevent updates to the admin role
        if getattr(self.instance, "name", None) == "admin":
            raise serializers.ValidationError(
                {"name": "The admin role cannot be updated."}
            )

        return super().validate(attrs)

    class Meta:
        model = Role
        fields = [
            "id",
            "name",
            "manage_users",
            "manage_account",
            # Disable for the first release
            # "manage_billing",
            # /Disable for the first release
            "manage_integrations",
            "manage_providers",
            "manage_scans",
            "permission_state",
            "unlimited_visibility",
            "inserted_at",
            "updated_at",
            "provider_groups",
            "users",
            "invitations",
            "url",
        ]
        extra_kwargs = {
            "id": {"read_only": True},
            "inserted_at": {"read_only": True},
            "updated_at": {"read_only": True},
            "url": {"read_only": True},
        }


class RoleCreateSerializer(RoleSerializer):
    provider_groups = serializers.ResourceRelatedField(
        many=True, queryset=ProviderGroup.objects.all(), required=False
    )
    users = serializers.ResourceRelatedField(
        many=True, queryset=User.objects.all(), required=False
    )

    def create(self, validated_data):
        provider_groups = validated_data.pop("provider_groups", [])
        users = validated_data.pop("users", [])
        tenant_id = self.context.get("tenant_id")
        role = Role.objects.create(tenant_id=tenant_id, **validated_data)

        through_model_instances = [
            RoleProviderGroupRelationship(
                role=role,
                provider_group=provider_group,
                tenant_id=tenant_id,
            )
            for provider_group in provider_groups
        ]
        RoleProviderGroupRelationship.objects.bulk_create(through_model_instances)

        through_model_instances = [
            UserRoleRelationship(
                role=role,
                user=user,
                tenant_id=tenant_id,
            )
            for user in users
        ]
        UserRoleRelationship.objects.bulk_create(through_model_instances)

        return role


class RoleUpdateSerializer(RoleSerializer):
    def update(self, instance, validated_data):
        tenant_id = self.context.get("tenant_id")

        if "provider_groups" in validated_data:
            provider_groups = validated_data.pop("provider_groups")
            instance.provider_groups.clear()
            through_model_instances = [
                RoleProviderGroupRelationship(
                    role=instance,
                    provider_group=provider_group,
                    tenant_id=tenant_id,
                )
                for provider_group in provider_groups
            ]
            RoleProviderGroupRelationship.objects.bulk_create(through_model_instances)

        if "users" in validated_data:
            users = validated_data.pop("users")
            # Prevent a user from removing their own role assignment via Role update
            request = self.context.get("request")
            if request and getattr(request, "user", None):
                request_user = request.user
                is_currently_assigned = instance.users.filter(
                    id=request_user.id
                ).exists()
                will_be_assigned = any(u.id == request_user.id for u in users)
                if is_currently_assigned and not will_be_assigned:
                    raise serializers.ValidationError(
                        {"users": "Users cannot remove their own role."}
                    )

            # Safeguard MANAGE_ACCOUNT coverage when updating users of this role
            if instance.manage_account:
                # Existing MANAGE_ACCOUNT assignments on other roles within the tenant
                other_ma_exists = (
                    UserRoleRelationship.objects.filter(
                        tenant_id=tenant_id, role__manage_account=True
                    )
                    .exclude(role_id=instance.id)
                    .exists()
                )

                if not other_ma_exists and len(users) == 0:
                    raise serializers.ValidationError(
                        {
                            "users": "At least one user in the tenant must retain MANAGE_ACCOUNT. "
                            "Assign this MANAGE_ACCOUNT role to at least one user or ensure another user has it."
                        }
                    )
            instance.users.clear()
            through_model_instances = [
                UserRoleRelationship(
                    role=instance,
                    user=user,
                    tenant_id=tenant_id,
                )
                for user in users
            ]
            UserRoleRelationship.objects.bulk_create(through_model_instances)

        return super().update(instance, validated_data)


class RoleIncludeSerializer(RLSSerializer):
    permission_state = serializers.SerializerMethodField()

    def get_permission_state(self, obj) -> str:
        return obj.permission_state

    class Meta:
        model = Role
        fields = [
            "id",
            "name",
            "manage_users",
            "manage_account",
            # Disable for the first release
            # "manage_billing",
            # /Disable for the first release
            "manage_integrations",
            "manage_providers",
            "manage_scans",
            "permission_state",
            "unlimited_visibility",
            "inserted_at",
            "updated_at",
        ]
        extra_kwargs = {
            "id": {"read_only": True},
            "inserted_at": {"read_only": True},
            "updated_at": {"read_only": True},
        }


class ProviderGroupResourceIdentifierSerializer(serializers.Serializer):
    resource_type = serializers.CharField(source="type")
    id = serializers.UUIDField()

    class JSONAPIMeta:
        resource_name = "provider-group-identifier"

    def to_representation(self, instance):
        """
        Ensure 'type' is used in the output instead of 'resource_type'.
        """
        representation = super().to_representation(instance)
        representation["type"] = representation.pop("resource_type", None)
        return representation

    def to_internal_value(self, data):
        """
        Map 'type' back to 'resource_type' during input.
        """
        data["resource_type"] = data.pop("type", None)
        return super().to_internal_value(data)


class RoleProviderGroupRelationshipSerializer(RLSSerializer, BaseWriteSerializer):
    """
    Serializer for modifying role memberships
    """

    provider_groups = serializers.ListField(
        child=ProviderGroupResourceIdentifierSerializer(),
        help_text="List of resource identifier objects representing provider groups.",
    )

    def create(self, validated_data):
        provider_group_ids = [item["id"] for item in validated_data["provider_groups"]]
        provider_groups = ProviderGroup.objects.filter(id__in=provider_group_ids)
        tenant_id = self.context.get("tenant_id")

        new_relationships = [
            RoleProviderGroupRelationship(
                role=self.context.get("role"), provider_group=pg, tenant_id=tenant_id
            )
            for pg in provider_groups
        ]
        RoleProviderGroupRelationship.objects.bulk_create(new_relationships)

        return self.context.get("role")

    def update(self, instance, validated_data):
        provider_group_ids = [item["id"] for item in validated_data["provider_groups"]]
        provider_groups = ProviderGroup.objects.filter(id__in=provider_group_ids)
        tenant_id = self.context.get("tenant_id")

        instance.provider_groups.clear()
        new_relationships = [
            RoleProviderGroupRelationship(
                role=instance, provider_group=pg, tenant_id=tenant_id
            )
            for pg in provider_groups
        ]
        RoleProviderGroupRelationship.objects.bulk_create(new_relationships)

        return instance

    class Meta:
        model = RoleProviderGroupRelationship
        fields = ["id", "provider_groups"]


# Compliance overview


class ComplianceOverviewSerializer(BaseSerializerV1):
    """
    Serializer for compliance requirement status aggregated by compliance framework.

    This serializer is used to format aggregated compliance framework data,
    providing counts of passed, failed, and manual requirements along with
    an overall global status for each framework.
    """

    # Add ID field which will be used for resource identification
    id = serializers.CharField()
    framework = serializers.CharField()
    version = serializers.CharField()
    requirements_passed = serializers.IntegerField()
    requirements_failed = serializers.IntegerField()
    requirements_manual = serializers.IntegerField()
    total_requirements = serializers.IntegerField()

    class JSONAPIMeta:
        resource_name = "compliance-overviews"


class ComplianceOverviewDetailSerializer(BaseSerializerV1):
    """
    Serializer for detailed compliance requirement information.

    This serializer formats the aggregated requirement data, showing detailed status
    and counts for each requirement across all regions.
    """

    id = serializers.CharField()
    framework = serializers.CharField()
    version = serializers.CharField()
    description = serializers.CharField()
    status = serializers.ChoiceField(choices=StatusChoices.choices)

    class JSONAPIMeta:
        resource_name = "compliance-requirements-details"


class ComplianceOverviewDetailThreatscoreSerializer(ComplianceOverviewDetailSerializer):
    """
    Serializer for detailed compliance requirement information for Threatscore.

    Includes additional fields specific to the Threatscore framework.
    """

    passed_findings = serializers.IntegerField()
    total_findings = serializers.IntegerField()


class ComplianceOverviewAttributesSerializer(BaseSerializerV1):
    id = serializers.CharField()
    compliance_name = serializers.CharField()
    framework_description = serializers.CharField()
    name = serializers.CharField()
    framework = serializers.CharField()
    version = serializers.CharField()
    description = serializers.CharField()
    attributes = serializers.JSONField()

    class JSONAPIMeta:
        resource_name = "compliance-requirements-attributes"


class ComplianceOverviewMetadataSerializer(BaseSerializerV1):
    regions = serializers.ListField(child=serializers.CharField(), allow_empty=True)

    class JSONAPIMeta:
        resource_name = "compliance-overviews-metadata"


# Overviews


class OverviewProviderSerializer(BaseSerializerV1):
    id = serializers.CharField(source="provider")
    findings = serializers.SerializerMethodField(read_only=True)
    resources = serializers.SerializerMethodField(read_only=True)

    class JSONAPIMeta:
        resource_name = "providers-overview"

    @extend_schema_field(
        {
            "type": "object",
            "properties": {
                "pass": {"type": "integer"},
                "fail": {"type": "integer"},
                "muted": {"type": "integer"},
                "total": {"type": "integer"},
            },
        }
    )
    def get_findings(self, obj):
        return {
            "pass": obj["findings_passed"],
            "fail": obj["findings_failed"],
            "muted": obj["findings_muted"],
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


class OverviewProviderCountSerializer(BaseSerializerV1):
    id = serializers.CharField(source="provider")
    count = serializers.IntegerField()

    class JSONAPIMeta:
        resource_name = "providers-count-overview"


class OverviewFindingSerializer(BaseSerializerV1):
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

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["pass"] = self.fields.pop("_pass")


class OverviewSeveritySerializer(BaseSerializerV1):
    id = serializers.CharField(default="n/a")
    critical = serializers.IntegerField()
    high = serializers.IntegerField()
    medium = serializers.IntegerField()
    low = serializers.IntegerField()
    informational = serializers.IntegerField()

    class JSONAPIMeta:
        resource_name = "findings-severity-overview"


class FindingsSeverityOverTimeSerializer(BaseSerializerV1):
    """Serializer for daily findings severity trend data."""

    id = serializers.DateField(source="date")
    critical = serializers.IntegerField()
    high = serializers.IntegerField()
    medium = serializers.IntegerField()
    low = serializers.IntegerField()
    informational = serializers.IntegerField()
    muted = serializers.IntegerField()
    scan_ids = serializers.ListField(child=serializers.UUIDField())

    class JSONAPIMeta:
        resource_name = "findings-severity-over-time"


class OverviewServiceSerializer(BaseSerializerV1):
    id = serializers.CharField(source="service")
    total = serializers.IntegerField()
    _pass = serializers.IntegerField()
    fail = serializers.IntegerField()
    muted = serializers.IntegerField()

    class JSONAPIMeta:
        resource_name = "services-overview"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["pass"] = self.fields.pop("_pass")


class AttackSurfaceOverviewSerializer(BaseSerializerV1):
    """Serializer for attack surface overview aggregations."""

    id = serializers.CharField(source="attack_surface_type")
    total_findings = serializers.IntegerField()
    failed_findings = serializers.IntegerField()
    muted_failed_findings = serializers.IntegerField()

    class JSONAPIMeta:
        resource_name = "attack-surface-overviews"


class CategoryOverviewSerializer(BaseSerializerV1):
    """Serializer for category overview aggregations."""

    id = serializers.CharField(source="category")
    total_findings = serializers.IntegerField()
    failed_findings = serializers.IntegerField()
    new_failed_findings = serializers.IntegerField()
    severity = serializers.JSONField(
        help_text="Severity breakdown: {informational, low, medium, high, critical}"
    )

    class JSONAPIMeta:
        resource_name = "category-overviews"


class ResourceGroupOverviewSerializer(BaseSerializerV1):
    """Serializer for resource group overview aggregations."""

    id = serializers.CharField(source="resource_group")
    total_findings = serializers.IntegerField()
    failed_findings = serializers.IntegerField()
    new_failed_findings = serializers.IntegerField()
    resources_count = serializers.IntegerField()
    severity = serializers.JSONField(
        help_text="Severity breakdown: {informational, low, medium, high, critical}"
    )

    class JSONAPIMeta:
        resource_name = "resource-group-overviews"


class ComplianceWatchlistOverviewSerializer(BaseSerializerV1):
    """Serializer for compliance watchlist overview with FAIL-dominant aggregation."""

    id = serializers.CharField(source="compliance_id")
    compliance_id = serializers.CharField()
    requirements_passed = serializers.IntegerField()
    requirements_failed = serializers.IntegerField()
    requirements_manual = serializers.IntegerField()
    total_requirements = serializers.IntegerField()

    class JSONAPIMeta:
        resource_name = "compliance-watchlist-overviews"


class OverviewRegionSerializer(serializers.Serializer):
    id = serializers.SerializerMethodField()
    provider_type = serializers.CharField()
    region = serializers.CharField()
    total = serializers.IntegerField()
    _pass = serializers.IntegerField()
    fail = serializers.IntegerField()
    muted = serializers.IntegerField()

    class JSONAPIMeta:
        resource_name = "regions-overview"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["pass"] = self.fields.pop("_pass")

    def get_id(self, obj):
        """Generate unique ID from provider_type and region."""
        return f"{obj['provider_type']}:{obj['region']}"

    def get_root_meta(self, _resource, _many):
        return {"version": "v1"}


# Schedules


class ScheduleDailyCreateSerializer(BaseSerializerV1):
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


# Integrations


class BaseWriteIntegrationSerializer(BaseWriteSerializer):
    def validate(self, attrs):
        integration_type = attrs.get("integration_type")

        if (
            integration_type == Integration.IntegrationChoices.AMAZON_S3
            and Integration.objects.filter(
                configuration=attrs.get("configuration")
            ).exists()
        ):
            raise ConflictException(
                detail="This integration already exists.",
                pointer="/data/attributes/configuration",
            )

        if (
            integration_type == Integration.IntegrationChoices.JIRA
            and Integration.objects.filter(
                configuration__contains={
                    "domain": attrs.get("configuration").get("domain")
                }
            ).exists()
        ):
            raise ConflictException(
                detail="This integration already exists.",
                pointer="/data/attributes/configuration",
            )

        # Check if any provider already has a SecurityHub integration
        if hasattr(self, "instance") and self.instance and not integration_type:
            integration_type = self.instance.integration_type

        if (
            integration_type == Integration.IntegrationChoices.AWS_SECURITY_HUB
            and "providers" in attrs
        ):
            providers = attrs.get("providers", [])
            tenant_id = self.context.get("tenant_id")
            for provider in providers:
                # For updates, exclude the current instance from the check
                query = IntegrationProviderRelationship.objects.filter(
                    provider=provider,
                    integration__integration_type=Integration.IntegrationChoices.AWS_SECURITY_HUB,
                    tenant_id=tenant_id,
                )
                if hasattr(self, "instance") and self.instance:
                    query = query.exclude(integration=self.instance)

                if query.exists():
                    raise ConflictException(
                        detail=f"Provider {provider.id} already has a Security Hub integration. Only one "
                        "Security Hub integration is allowed per provider.",
                        pointer="/data/relationships/providers",
                    )

        return super().validate(attrs)

    @staticmethod
    def validate_integration_data(
        integration_type: str,
        providers: list[Provider],  # noqa
        configuration: dict,
        credentials: dict,
    ):
        if integration_type == Integration.IntegrationChoices.AMAZON_S3:
            config_serializer = S3ConfigSerializer
            credentials_serializers = [AWSCredentialSerializer]
        elif integration_type == Integration.IntegrationChoices.AWS_SECURITY_HUB:
            if providers:
                if len(providers) > 1:
                    raise serializers.ValidationError(
                        {
                            "providers": "Only one provider is supported for the Security Hub integration."
                        }
                    )
                if providers[0].provider != Provider.ProviderChoices.AWS:
                    raise serializers.ValidationError(
                        {
                            "providers": "The provider must be AWS type for the Security Hub integration."
                        }
                    )
            config_serializer = SecurityHubConfigSerializer
            credentials_serializers = [AWSCredentialSerializer]
        elif integration_type == Integration.IntegrationChoices.JIRA:
            if providers:
                raise serializers.ValidationError(
                    {
                        "providers": "Relationship field is not accepted. This integration applies to all providers."
                    }
                )
            if configuration:
                raise serializers.ValidationError(
                    {
                        "configuration": "This integration does not support custom configuration."
                    }
                )
            config_serializer = JiraConfigSerializer
            # Create non-editable configuration for JIRA integration
            default_jira_issue_types = ["Task"]
            configuration.update(
                {
                    "projects": {},
                    "issue_types": default_jira_issue_types,
                    "domain": credentials.get("domain"),
                }
            )
            credentials_serializers = [JiraCredentialSerializer]
        else:
            raise serializers.ValidationError(
                {
                    "integration_type": f"Integration type not supported yet: {integration_type}"
                }
            )

        serializer_instance = config_serializer(data=configuration)
        serializer_instance.is_valid(raise_exception=True)

        # Apply the validated (and potentially transformed) data back to configuration
        configuration.update(serializer_instance.validated_data)

        for cred_serializer in credentials_serializers:
            try:
                cred_serializer(data=credentials).is_valid(raise_exception=True)
                break
            except ValidationError:
                continue
        else:
            raise ValidationError(
                {"credentials": "Invalid credentials for the integration type."}
            )


class IntegrationSerializer(RLSSerializer):
    """
    Serializer for the Integration model.
    """

    providers = serializers.ResourceRelatedField(
        queryset=Provider.objects.all(), many=True
    )

    class Meta:
        model = Integration
        fields = [
            "id",
            "inserted_at",
            "updated_at",
            "enabled",
            "connected",
            "connection_last_checked_at",
            "integration_type",
            "configuration",
            "providers",
            "url",
        ]

    included_serializers = {
        "providers": "api.v1.serializers.ProviderIncludeSerializer",
    }

    def to_representation(self, instance):
        representation = super().to_representation(instance)
        allowed_providers = self.context.get("allowed_providers")
        if allowed_providers:
            allowed_provider_ids = {str(provider.id) for provider in allowed_providers}
            representation["providers"] = [
                provider
                for provider in representation["providers"]
                if provider["id"] in allowed_provider_ids
            ]
        if instance.integration_type == Integration.IntegrationChoices.JIRA:
            representation["configuration"].update(
                {"domain": instance.credentials.get("domain")}
            )
        return representation


class IntegrationCreateSerializer(BaseWriteIntegrationSerializer):
    credentials = IntegrationCredentialField(write_only=True)
    configuration = IntegrationConfigField()
    providers = serializers.ResourceRelatedField(
        queryset=Provider.objects.all(), many=True, required=False
    )

    class Meta:
        model = Integration
        fields = [
            "inserted_at",
            "updated_at",
            "enabled",
            "connected",
            "connection_last_checked_at",
            "integration_type",
            "configuration",
            "credentials",
            "providers",
        ]
        extra_kwargs = {
            "inserted_at": {"read_only": True},
            "updated_at": {"read_only": True},
            "connected": {"read_only": True},
            "connection_last_checked_at": {"read_only": True},
        }

    def validate(self, attrs):
        integration_type = attrs.get("integration_type")
        providers = attrs.get("providers")
        configuration = attrs.get("configuration")
        credentials = attrs.get("credentials")

        if (
            not providers
            and integration_type == Integration.IntegrationChoices.AWS_SECURITY_HUB
        ):
            raise serializers.ValidationError(
                {"providers": "At least one provider is required for this integration."}
            )

        self.validate_integration_data(
            integration_type, providers, configuration, credentials
        )
        validated_attrs = super().validate(attrs)
        return validated_attrs

    def create(self, validated_data):
        tenant_id = self.context.get("tenant_id")

        providers = validated_data.pop("providers", [])
        integration = Integration.objects.create(tenant_id=tenant_id, **validated_data)

        through_model_instances = [
            IntegrationProviderRelationship(
                integration=integration,
                provider=provider,
                tenant_id=tenant_id,
            )
            for provider in providers
        ]
        IntegrationProviderRelationship.objects.bulk_create(through_model_instances)

        return integration


class IntegrationUpdateSerializer(BaseWriteIntegrationSerializer):
    credentials = IntegrationCredentialField(write_only=True, required=False)
    configuration = IntegrationConfigField(required=False)
    providers = serializers.ResourceRelatedField(
        queryset=Provider.objects.all(), many=True, required=False
    )

    class Meta:
        model = Integration
        fields = [
            "inserted_at",
            "updated_at",
            "enabled",
            "connected",
            "connection_last_checked_at",
            "integration_type",
            "configuration",
            "credentials",
            "providers",
        ]
        extra_kwargs = {
            "inserted_at": {"read_only": True},
            "updated_at": {"read_only": True},
            "connected": {"read_only": True},
            "connection_last_checked_at": {"read_only": True},
            "integration_type": {"read_only": True},
        }

    def validate(self, attrs):
        integration_type = self.instance.integration_type
        providers = attrs.get("providers")
        if integration_type != Integration.IntegrationChoices.JIRA:
            configuration = attrs.get("configuration") or self.instance.configuration
        else:
            configuration = attrs.get("configuration", {})
        credentials = attrs.get("credentials") or self.instance.credentials

        self.validate_integration_data(
            integration_type, providers, configuration, credentials
        )
        validated_attrs = super().validate(attrs)
        return validated_attrs

    def update(self, instance, validated_data):
        tenant_id = self.context.get("tenant_id")
        if validated_data.get("providers") is not None:
            instance.providers.clear()
            new_relationships = [
                IntegrationProviderRelationship(
                    integration=instance, provider=provider, tenant_id=tenant_id
                )
                for provider in validated_data["providers"]
            ]
            IntegrationProviderRelationship.objects.bulk_create(new_relationships)

        # Preserve regions field for Security Hub integrations
        if instance.integration_type == Integration.IntegrationChoices.AWS_SECURITY_HUB:
            if "configuration" in validated_data:
                # Preserve the existing regions field if it exists
                existing_regions = instance.configuration.get("regions", {})
                validated_data["configuration"]["regions"] = existing_regions

        return super().update(instance, validated_data)

    def to_representation(self, instance):
        representation = super().to_representation(instance)
        # Ensure JIRA integrations show updated domain in configuration from credentials
        if instance.integration_type == Integration.IntegrationChoices.JIRA:
            representation["configuration"].update(
                {"domain": instance.credentials.get("domain")}
            )
        return representation


class IntegrationJiraDispatchSerializer(BaseSerializerV1):
    """
    Serializer for dispatching findings to JIRA integration.
    """

    project_key = serializers.CharField(required=True)
    issue_type = serializers.ChoiceField(required=True, choices=["Task"])

    class JSONAPIMeta:
        resource_name = "integrations-jira-dispatches"

    def validate(self, attrs):
        validated_attrs = super().validate(attrs)
        integration_instance = Integration.objects.get(
            id=self.context.get("integration_id")
        )
        if integration_instance.integration_type != Integration.IntegrationChoices.JIRA:
            raise ValidationError(
                {"integration_type": "The given integration is not a JIRA integration"}
            )

        if not integration_instance.enabled:
            raise ValidationError(
                {"integration": "The given integration is not enabled"}
            )

        project_key = attrs.get("project_key")
        if project_key not in integration_instance.configuration.get("projects", {}):
            raise ValidationError(
                {
                    "project_key": "The given project key is not available for this JIRA integration. Refresh the "
                    "connection if this is an error."
                }
            )

        return validated_attrs


# Processors


class ProcessorSerializer(RLSSerializer):
    """
    Serializer for the Processor model.
    """

    configuration = ProcessorConfigField()

    class Meta:
        model = Processor
        fields = [
            "id",
            "inserted_at",
            "updated_at",
            "processor_type",
            "configuration",
            "url",
        ]


class ProcessorCreateSerializer(RLSSerializer, BaseWriteSerializer):
    configuration = ProcessorConfigField(required=True)

    class Meta:
        model = Processor
        fields = [
            "inserted_at",
            "updated_at",
            "processor_type",
            "configuration",
        ]
        extra_kwargs = {
            "inserted_at": {"read_only": True},
            "updated_at": {"read_only": True},
        }
        validators = [
            UniqueTogetherValidator(
                queryset=Processor.objects.all(),
                fields=["processor_type"],
                message="A processor with the same type already exists.",
            )
        ]

    def validate(self, attrs):
        validated_attrs = super().validate(attrs)
        self.validate_processor_data(attrs)
        return validated_attrs

    def validate_processor_data(self, attrs):
        processor_type = attrs.get("processor_type")
        configuration = attrs.get("configuration")
        if processor_type == "mutelist":
            self.validate_mutelist_configuration(configuration)

    def validate_mutelist_configuration(self, configuration):
        if not isinstance(configuration, dict):
            raise serializers.ValidationError("Invalid Mutelist configuration.")

        mutelist_configuration = configuration.get("Mutelist", {})

        if not mutelist_configuration:
            raise serializers.ValidationError(
                "Invalid Mutelist configuration: 'Mutelist' is a required property."
            )

        try:
            Mutelist.validate_mutelist(mutelist_configuration, raise_on_exception=True)
            return
        except Exception as error:
            raise serializers.ValidationError(
                f"Invalid Mutelist configuration: {error}"
            )


class ProcessorUpdateSerializer(BaseWriteSerializer):
    configuration = ProcessorConfigField(required=True)

    class Meta:
        model = Processor
        fields = [
            "inserted_at",
            "updated_at",
            "configuration",
        ]
        extra_kwargs = {
            "inserted_at": {"read_only": True},
            "updated_at": {"read_only": True},
        }

    def validate(self, attrs):
        validated_attrs = super().validate(attrs)
        self.validate_processor_data(attrs)
        return validated_attrs

    def validate_processor_data(self, attrs):
        processor_type = self.instance.processor_type
        configuration = attrs.get("configuration")
        if processor_type == "mutelist":
            self.validate_mutelist_configuration(configuration)

    def validate_mutelist_configuration(self, configuration):
        if not isinstance(configuration, dict):
            raise serializers.ValidationError("Invalid Mutelist configuration.")

        mutelist_configuration = configuration.get("Mutelist", {})

        if not mutelist_configuration:
            raise serializers.ValidationError(
                "Invalid Mutelist configuration: 'Mutelist' is a required property."
            )

        try:
            Mutelist.validate_mutelist(mutelist_configuration, raise_on_exception=True)
            return
        except Exception as error:
            raise serializers.ValidationError(
                f"Invalid Mutelist configuration: {error}"
            )


# SSO


class SamlInitiateSerializer(BaseSerializerV1):
    email_domain = serializers.CharField()

    class JSONAPIMeta:
        resource_name = "saml-initiate"


class SamlMetadataSerializer(BaseSerializerV1):
    class JSONAPIMeta:
        resource_name = "saml-meta"


class SAMLConfigurationSerializer(RLSSerializer):
    class Meta:
        model = SAMLConfiguration
        fields = ["id", "email_domain", "metadata_xml", "created_at", "updated_at"]
        read_only_fields = ["id", "created_at", "updated_at"]


class LighthouseConfigSerializer(RLSSerializer):
    """
    Serializer for the LighthouseConfig model.
    """

    api_key = serializers.CharField(required=False)

    class Meta:
        model = LighthouseConfiguration
        fields = [
            "id",
            "name",
            "api_key",
            "model",
            "temperature",
            "max_tokens",
            "business_context",
            "is_active",
            "inserted_at",
            "updated_at",
            "url",
        ]
        extra_kwargs = {
            "id": {"read_only": True},
            "is_active": {"read_only": True},
            "inserted_at": {"read_only": True},
            "updated_at": {"read_only": True},
        }

    def to_representation(self, instance):
        data = super().to_representation(instance)
        # Check if api_key is specifically requested in fields param
        fields_param = self.context.get("request", None) and self.context[
            "request"
        ].query_params.get("fields[lighthouse-config]", "")
        if fields_param == "api_key":
            # Return decrypted key if specifically requested
            data["api_key"] = instance.api_key_decoded if instance.api_key else None
        else:
            # Return masked key for general requests
            data["api_key"] = "*" * len(instance.api_key) if instance.api_key else None
        return data


class LighthouseConfigCreateSerializer(RLSSerializer, BaseWriteSerializer):
    """Serializer for creating new Lighthouse configurations."""

    api_key = serializers.CharField(write_only=True, required=True)

    class Meta:
        model = LighthouseConfiguration
        fields = [
            "id",
            "name",
            "api_key",
            "model",
            "temperature",
            "max_tokens",
            "business_context",
            "is_active",
            "inserted_at",
            "updated_at",
        ]
        extra_kwargs = {
            "id": {"read_only": True},
            "is_active": {"read_only": True},
            "inserted_at": {"read_only": True},
            "updated_at": {"read_only": True},
        }

    def validate_temperature(self, value):
        if not 0 <= value <= 1:
            raise ValidationError("Temperature must be between 0 and 1.")
        return value

    def validate_max_tokens(self, value):
        if not 500 <= value <= 5000:
            raise ValidationError("Max tokens must be between 500 and 5000.")
        return value

    def validate(self, attrs):
        tenant_id = self.context.get("request").tenant_id
        if LighthouseConfiguration.objects.filter(tenant_id=tenant_id).exists():
            raise serializers.ValidationError(
                {
                    "tenant_id": "Lighthouse configuration already exists for this tenant."
                }
            )
        api_key = attrs.get("api_key")
        if api_key is not None:
            OpenAICredentialsSerializer(data={"api_key": api_key}).is_valid(
                raise_exception=True
            )
        return super().validate(attrs)

    def create(self, validated_data):
        api_key = validated_data.pop("api_key")
        instance = super().create(validated_data)
        instance.api_key_decoded = api_key
        instance.save()
        return instance

    def to_representation(self, instance):
        data = super().to_representation(instance)
        # Always mask the API key in the response
        data["api_key"] = "*" * len(instance.api_key) if instance.api_key else None
        return data


class LighthouseConfigUpdateSerializer(BaseWriteSerializer):
    """
    Serializer for updating LighthouseConfig instances.
    """

    api_key = serializers.CharField(write_only=True, required=False)

    class Meta:
        model = LighthouseConfiguration
        fields = [
            "id",
            "name",
            "api_key",
            "model",
            "temperature",
            "max_tokens",
            "business_context",
            "is_active",
        ]
        extra_kwargs = {
            "id": {"read_only": True},
            "is_active": {"read_only": True},
            "name": {"required": False},
            "model": {"required": False},
            "temperature": {"required": False},
            "max_tokens": {"required": False},
        }

    def validate_temperature(self, value):
        if not 0 <= value <= 1:
            raise ValidationError("Temperature must be between 0 and 1.")
        return value

    def validate_max_tokens(self, value):
        if not 500 <= value <= 5000:
            raise ValidationError("Max tokens must be between 500 and 5000.")
        return value

    def validate(self, attrs):
        api_key = attrs.get("api_key", None)
        if api_key is not None:
            OpenAICredentialsSerializer(data={"api_key": api_key}).is_valid(
                raise_exception=True
            )
        return super().validate(attrs)

    def update(self, instance, validated_data):
        api_key = validated_data.pop("api_key", None)
        instance = super().update(instance, validated_data)
        if api_key:
            instance.api_key_decoded = api_key
            instance.save()
        return instance


# API Keys


class TenantApiKeySerializer(RLSSerializer):
    """
    Serializer for the TenantApiKey model.
    """

    # Map database field names to API field names for consistency
    expires_at = serializers.DateTimeField(source="expiry_date", read_only=True)
    inserted_at = serializers.DateTimeField(source="created", read_only=True)

    class Meta:
        model = TenantAPIKey
        fields = [
            "id",
            "name",
            "prefix",
            "expires_at",
            "revoked",
            "inserted_at",
            "last_used_at",
            "entity",
        ]

    included_serializers = {
        "entity": "api.v1.serializers.UserIncludeSerializer",
    }


class TenantApiKeyCreateSerializer(RLSSerializer, BaseWriteSerializer):
    """Serializer for creating new API keys."""

    # Map database field names to API field names for consistency
    expires_at = serializers.DateTimeField(source="expiry_date", required=False)
    inserted_at = serializers.DateTimeField(source="created", read_only=True)
    api_key = serializers.SerializerMethodField()

    class Meta:
        model = TenantAPIKey
        fields = [
            "id",
            "name",
            "prefix",
            "expires_at",
            "revoked",
            "entity",
            "inserted_at",
            "last_used_at",
            "api_key",
        ]
        extra_kwargs = {
            "id": {"read_only": True},
            "prefix": {"read_only": True},
            "revoked": {"read_only": True},
            "entity": {"read_only": True},
            "inserted_at": {"read_only": True},
            "last_used_at": {"read_only": True},
            "api_key": {"read_only": True},
        }

    def validate_name(self, value):
        """Validate that the name is unique within the tenant."""
        tenant_id = self.context.get("tenant_id")
        if TenantAPIKey.objects.filter(tenant_id=tenant_id, name=value).exists():
            raise ValidationError("An API key with this name already exists.")
        return value

    def get_api_key(self, obj):
        """Return the raw API key if it was stored during creation."""
        return getattr(obj, "_raw_api_key", None)

    def create(self, validated_data):
        instance, raw_api_key = TenantAPIKey.objects.create_api_key(
            **validated_data,
            tenant_id=self.context.get("tenant_id"),
            entity=self.context.get("request").user,
        )
        # Store the raw API key temporarily on the instance for the serializer
        instance._raw_api_key = raw_api_key
        return instance


class TenantApiKeyUpdateSerializer(RLSSerializer, BaseWriteSerializer):
    """Serializer for updating API keys - only allows changing the name."""

    # Map database field names to API field names for consistency
    expires_at = serializers.DateTimeField(source="expiry_date", read_only=True)
    inserted_at = serializers.DateTimeField(source="created", read_only=True)

    class Meta:
        model = TenantAPIKey
        fields = [
            "id",
            "name",
            "prefix",
            "expires_at",
            "entity",
            "inserted_at",
            "last_used_at",
        ]
        extra_kwargs = {
            "id": {"read_only": True},
            "prefix": {"read_only": True},
            "entity": {"read_only": True},
            "expires_at": {"read_only": True},
            "inserted_at": {"read_only": True},
            "last_used_at": {"read_only": True},
        }

    def validate_name(self, value):
        """Validate that the name is unique within the tenant, excluding current instance."""
        tenant_id = self.context.get("tenant_id")
        if (
            TenantAPIKey.objects.filter(tenant_id=tenant_id, name=value)
            .exclude(id=self.instance.id)
            .exists()
        ):
            raise ValidationError("An API key with this name already exists.")
        return value


# Lighthouse: Provider configurations


class LighthouseProviderConfigSerializer(RLSSerializer):
    """
    Read serializer for LighthouseProviderConfiguration.
    """

    # Decrypted credentials are only returned in to_representation when requested
    credentials = serializers.JSONField(required=False, read_only=True)

    class Meta:
        model = LighthouseProviderConfiguration
        fields = [
            "id",
            "inserted_at",
            "updated_at",
            "provider_type",
            "base_url",
            "is_active",
            "credentials",
            "url",
        ]
        extra_kwargs = {
            "id": {"read_only": True},
            "inserted_at": {"read_only": True},
            "updated_at": {"read_only": True},
            "is_active": {"read_only": True},
            "url": {"read_only": True, "view_name": "lighthouse-providers-detail"},
        }

    class JSONAPIMeta:
        resource_name = "lighthouse-providers"

    def to_representation(self, instance):
        data = super().to_representation(instance)
        # Support JSON:API fields filter: fields[lighthouse-providers]=credentials,base_url
        fields_param = self.context.get("request", None) and self.context[
            "request"
        ].query_params.get("fields[lighthouse-providers]", "")

        creds = instance.credentials_decoded

        requested_fields = (
            [f.strip() for f in fields_param.split(",")] if fields_param else []
        )

        if "credentials" in requested_fields:
            # Return full decrypted credentials JSON
            data["credentials"] = creds
        else:
            # Return masked credentials by default
            def mask_value(value):
                if isinstance(value, str):
                    return "*" * len(value)
                if isinstance(value, dict):
                    return {k: mask_value(v) for k, v in value.items()}
                if isinstance(value, list):
                    return [mask_value(v) for v in value]
                return value

            # Always return masked credentials, even if creds is None
            if creds is not None:
                data["credentials"] = mask_value(creds)
            else:
                # If credentials_decoded returns None, return None for credentials field
                data["credentials"] = None

        return data


class LighthouseProviderConfigCreateSerializer(RLSSerializer, BaseWriteSerializer):
    """
    Create serializer for LighthouseProviderConfiguration.
    Accepts credentials as JSON; stored encrypted via credentials_decoded.
    """

    credentials = LighthouseCredentialsField(write_only=True, required=True)
    base_url = serializers.URLField(
        required=False,
        allow_null=True,
        help_text="Base URL for the LLM provider API. Required for 'openai_compatible' provider type.",
    )

    class Meta:
        model = LighthouseProviderConfiguration
        fields = [
            "provider_type",
            "base_url",
            "credentials",
            "is_active",
        ]
        extra_kwargs = {
            "is_active": {"required": False},
            "provider_type": {
                "help_text": "LLM provider type. Determines which credential format to use. "
                "See 'credentials' field documentation for provider-specific requirements."
            },
        }

    def create(self, validated_data):
        credentials = validated_data.pop("credentials")

        instance = LighthouseProviderConfiguration(**validated_data)
        instance.tenant_id = self.context.get("tenant_id")
        instance.credentials_decoded = credentials

        try:
            instance.save()
            return instance
        except IntegrityError:
            raise ValidationError(
                {
                    "provider_type": "Configuration for this provider already exists for the tenant."
                }
            )

    def validate(self, attrs):
        provider_type = attrs.get("provider_type")
        credentials = attrs.get("credentials") or {}
        base_url = attrs.get("base_url")

        if provider_type == LighthouseProviderConfiguration.LLMProviderChoices.OPENAI:
            try:
                OpenAICredentialsSerializer(data=credentials).is_valid(
                    raise_exception=True
                )
            except ValidationError as e:
                details = e.detail.copy()
                for key, value in details.items():
                    e.detail[f"credentials/{key}"] = value
                    del e.detail[key]
                raise e
        elif (
            provider_type == LighthouseProviderConfiguration.LLMProviderChoices.BEDROCK
        ):
            try:
                BedrockCredentialsSerializer(data=credentials).is_valid(
                    raise_exception=True
                )
            except ValidationError as e:
                details = e.detail.copy()
                for key, value in details.items():
                    e.detail[f"credentials/{key}"] = value
                    del e.detail[key]
                raise e
        elif (
            provider_type
            == LighthouseProviderConfiguration.LLMProviderChoices.OPENAI_COMPATIBLE
        ):
            if not base_url:
                raise ValidationError({"base_url": "Base URL is required."})
            try:
                OpenAICompatibleCredentialsSerializer(data=credentials).is_valid(
                    raise_exception=True
                )
            except ValidationError as e:
                details = e.detail.copy()
                for key, value in details.items():
                    e.detail[f"credentials/{key}"] = value
                    del e.detail[key]
                raise e

        return super().validate(attrs)


class LighthouseProviderConfigUpdateSerializer(BaseWriteSerializer):
    """
    Update serializer for LighthouseProviderConfiguration.
    """

    credentials = LighthouseCredentialsField(write_only=True, required=False)
    base_url = serializers.URLField(
        required=False,
        allow_null=True,
        help_text="Base URL for the LLM provider API. Required for 'openai_compatible' provider type.",
    )

    class Meta:
        model = LighthouseProviderConfiguration
        fields = [
            "id",
            "provider_type",
            "base_url",
            "credentials",
            "is_active",
        ]
        extra_kwargs = {
            "id": {"read_only": True},
            "provider_type": {"read_only": True},
            "is_active": {"required": False},
        }

    def update(self, instance, validated_data):
        credentials = validated_data.pop("credentials", None)

        for attr, value in validated_data.items():
            setattr(instance, attr, value)

        if credentials is not None:
            # Merge partial credentials with existing ones
            # New values overwrite existing ones, but unspecified fields are preserved
            existing_credentials = instance.credentials_decoded or {}
            merged_credentials = {**existing_credentials, **credentials}
            instance.credentials_decoded = merged_credentials

        instance.save()
        return instance

    def validate(self, attrs):
        provider_type = getattr(self.instance, "provider_type", None)
        credentials = attrs.get("credentials", None)
        base_url = attrs.get("base_url", None)

        if (
            credentials is not None
            and provider_type
            == LighthouseProviderConfiguration.LLMProviderChoices.OPENAI
        ):
            try:
                OpenAICredentialsSerializer(data=credentials).is_valid(
                    raise_exception=True
                )
            except ValidationError as e:
                details = e.detail.copy()
                for key, value in details.items():
                    e.detail[f"credentials/{key}"] = value
                    del e.detail[key]
                raise e
        elif (
            credentials is not None
            and provider_type
            == LighthouseProviderConfiguration.LLMProviderChoices.BEDROCK
        ):
            # For updates, enforce that the authentication method (access keys vs API key)
            # is immutable. To switch methods, the UI must delete and recreate the provider.
            existing_credentials = (
                self.instance.credentials_decoded if self.instance else {}
            ) or {}

            existing_uses_api_key = "api_key" in existing_credentials
            existing_uses_access_keys = any(
                k in existing_credentials
                for k in ("access_key_id", "secret_access_key")
            )

            # First run field-level validation on the partial payload
            try:
                BedrockCredentialsUpdateSerializer(data=credentials).is_valid(
                    raise_exception=True
                )
            except ValidationError as e:
                details = e.detail.copy()
                for key, value in details.items():
                    e.detail[f"credentials/{key}"] = value
                    del e.detail[key]
                raise e

            # Then enforce invariants about not changing the auth method
            # If the existing config uses an API key, forbid introducing access keys.
            if existing_uses_api_key and any(
                k in credentials for k in ("access_key_id", "secret_access_key")
            ):
                raise ValidationError(
                    {
                        "credentials/non_field_errors": [
                            "Cannot change Bedrock authentication method from API key "
                            "to access key via update. Delete and recreate the provider instead."
                        ]
                    }
                )

            # If the existing config uses access keys, forbid introducing an API key.
            if existing_uses_access_keys and "api_key" in credentials:
                raise ValidationError(
                    {
                        "credentials/non_field_errors": [
                            "Cannot change Bedrock authentication method from access key "
                            "to API key via update. Delete and recreate the provider instead."
                        ]
                    }
                )
        elif (
            credentials is not None
            and provider_type
            == LighthouseProviderConfiguration.LLMProviderChoices.OPENAI_COMPATIBLE
        ):
            if base_url is None:
                pass
            elif not base_url:
                raise ValidationError({"base_url": "Base URL cannot be empty."})
            try:
                OpenAICompatibleCredentialsSerializer(data=credentials).is_valid(
                    raise_exception=True
                )
            except ValidationError as e:
                details = e.detail.copy()
                for key, value in details.items():
                    e.detail[f"credentials/{key}"] = value
                    del e.detail[key]
                raise e

        return super().validate(attrs)


# Lighthouse: Tenant configuration


class LighthouseTenantConfigSerializer(RLSSerializer):
    """
    Read serializer for LighthouseTenantConfiguration.
    """

    # Build singleton URL without pk
    url = serializers.SerializerMethodField()

    def get_url(self, obj):
        request = self.context.get("request")
        return reverse("lighthouse-configurations", request=request)

    class Meta:
        model = LighthouseTenantConfiguration
        fields = [
            "id",
            "inserted_at",
            "updated_at",
            "business_context",
            "default_provider",
            "default_models",
            "url",
        ]
        extra_kwargs = {
            "id": {"read_only": True},
            "inserted_at": {"read_only": True},
            "updated_at": {"read_only": True},
            "url": {"read_only": True},
        }


class LighthouseTenantConfigUpdateSerializer(BaseWriteSerializer):
    class Meta:
        model = LighthouseTenantConfiguration
        fields = [
            "id",
            "business_context",
            "default_provider",
            "default_models",
        ]
        extra_kwargs = {
            "id": {"read_only": True},
        }

    def validate(self, attrs):
        request = self.context.get("request")
        tenant_id = self.context.get("tenant_id") or (
            getattr(request, "tenant_id", None) if request else None
        )

        default_provider = attrs.get(
            "default_provider", getattr(self.instance, "default_provider", "")
        )
        default_models = attrs.get(
            "default_models", getattr(self.instance, "default_models", {})
        )

        if default_provider:
            supported = set(LighthouseProviderConfiguration.LLMProviderChoices.values)
            if default_provider not in supported:
                raise ValidationError(
                    {"default_provider": f"Unsupported provider '{default_provider}'."}
                )
            if not LighthouseProviderConfiguration.objects.filter(
                tenant_id=tenant_id, provider_type=default_provider, is_active=True
            ).exists():
                raise ValidationError(
                    {
                        "default_provider": f"No active configuration found for '{default_provider}'."
                    }
                )

        if default_models is not None and not isinstance(default_models, dict):
            raise ValidationError(
                {"default_models": "Must be an object mapping provider -> model_id."}
            )

        for provider_type, model_id in (default_models or {}).items():
            provider_cfg = LighthouseProviderConfiguration.objects.filter(
                tenant_id=tenant_id, provider_type=provider_type, is_active=True
            ).first()
            if not provider_cfg:
                raise ValidationError(
                    {
                        "default_models": f"No active configuration for provider '{provider_type}'."
                    }
                )
            if not LighthouseProviderModels.objects.filter(
                tenant_id=tenant_id,
                provider_configuration=provider_cfg,
                model_id=model_id,
            ).exists():
                raise ValidationError(
                    {
                        "default_models": f"Invalid model '{model_id}' for provider '{provider_type}'."
                    }
                )

        return super().validate(attrs)


# Lighthouse: Provider models


class LighthouseProviderModelsSerializer(RLSSerializer):
    """
    Read serializer for LighthouseProviderModels.
    """

    provider_configuration = serializers.ResourceRelatedField(read_only=True)

    class Meta:
        model = LighthouseProviderModels
        fields = [
            "id",
            "inserted_at",
            "updated_at",
            "provider_configuration",
            "model_id",
            "model_name",
            "default_parameters",
            "url",
        ]
        extra_kwargs = {
            "id": {"read_only": True},
            "inserted_at": {"read_only": True},
            "updated_at": {"read_only": True},
            "url": {"read_only": True, "view_name": "lighthouse-models-detail"},
        }


class LighthouseProviderModelsCreateSerializer(RLSSerializer, BaseWriteSerializer):
    provider_configuration = serializers.ResourceRelatedField(
        queryset=LighthouseProviderConfiguration.objects.all()
    )

    class Meta:
        model = LighthouseProviderModels
        fields = [
            "provider_configuration",
            "model_id",
            "default_parameters",
        ]
        extra_kwargs = {
            "default_parameters": {"required": False},
        }


class LighthouseProviderModelsUpdateSerializer(BaseWriteSerializer):
    class Meta:
        model = LighthouseProviderModels
        fields = [
            "id",
            "default_parameters",
        ]
        extra_kwargs = {
            "id": {"read_only": True},
        }


# Mute Rules


class MuteRuleSerializer(RLSSerializer):
    """
    Serializer for reading MuteRule instances.
    """

    finding_uids = serializers.ListField(
        child=serializers.CharField(),
        read_only=True,
        help_text="List of finding UIDs that are muted by this rule",
    )

    class Meta:
        model = MuteRule
        fields = [
            "id",
            "inserted_at",
            "updated_at",
            "name",
            "reason",
            "enabled",
            "created_by",
            "finding_uids",
        ]

    included_serializers = {
        "created_by": "api.v1.serializers.UserIncludeSerializer",
    }


class MuteRuleCreateSerializer(RLSSerializer, BaseWriteSerializer):
    """
    Serializer for creating new MuteRule instances.

    Accepts finding_ids in the request, converts them to UIDs, and stores in finding_uids.
    """

    finding_ids = serializers.ListField(
        child=serializers.UUIDField(),
        write_only=True,
        required=True,
        help_text="List of Finding IDs to mute (will be converted to UIDs)",
    )
    finding_uids = serializers.ListField(
        child=serializers.CharField(),
        read_only=True,
        help_text="List of finding UIDs that are muted by this rule",
    )

    class Meta:
        model = MuteRule
        fields = [
            "id",
            "inserted_at",
            "updated_at",
            "name",
            "reason",
            "enabled",
            "created_by",
            "finding_ids",
            "finding_uids",
        ]
        extra_kwargs = {
            "id": {"read_only": True},
            "inserted_at": {"read_only": True},
            "updated_at": {"read_only": True},
            "enabled": {"read_only": True},
            "created_by": {"read_only": True},
        }

    def validate_name(self, value):
        """Validate that the name is unique within the tenant."""
        tenant_id = self.context.get("tenant_id")
        if MuteRule.objects.filter(tenant_id=tenant_id, name=value).exists():
            raise ValidationError("A mute rule with this name already exists.")
        return value

    def validate_finding_ids(self, value):
        """Validate that all finding IDs exist and belong to the tenant."""
        if not value:
            raise ValidationError("At least one finding_id must be provided.")

        tenant_id = self.context.get("tenant_id")

        # Check that all findings exist and belong to this tenant
        findings = Finding.all_objects.filter(tenant_id=tenant_id, id__in=value)
        found_ids = set(findings.values_list("id", flat=True))
        provided_ids = set(value)

        missing_ids = provided_ids - found_ids
        if missing_ids:
            raise ValidationError(
                f"The following finding IDs do not exist or do not belong to your tenant: {missing_ids}"
            )

        return value

    def validate(self, data):
        """Validate the entire mute rule, including overlap detection."""
        data = super().validate(data)

        tenant_id = self.context.get("tenant_id")
        finding_ids = data.get("finding_ids", [])

        if not finding_ids:
            return data

        # Convert finding IDs to UIDs (deduplicate in case multiple findings have same UID)
        findings = Finding.all_objects.filter(id__in=finding_ids, tenant_id=tenant_id)
        finding_uids = list(set(findings.values_list("uid", flat=True)))

        # Check for overlaps with existing enabled rules
        existing_rules = MuteRule.objects.filter(tenant_id=tenant_id, enabled=True)

        for rule in existing_rules:
            overlap = set(finding_uids) & set(rule.finding_uids)
            if overlap:
                raise ConflictException(
                    detail=f"The following finding UIDs are already muted by rule '{rule.name}': {overlap}"
                )

        # Store finding_uids in validated_data for create
        data["finding_uids"] = finding_uids

        return data

    def create(self, validated_data):
        """Create a new mute rule and set created_by."""
        # Remove finding_ids from validated_data (we've already converted to finding_uids)
        validated_data.pop("finding_ids", None)

        # Set created_by to the current user
        request = self.context.get("request")
        if request and hasattr(request, "user"):
            validated_data["created_by"] = request.user

        return super().create(validated_data)


class MuteRuleUpdateSerializer(BaseWriteSerializer):
    """
    Serializer for updating MuteRule instances.
    """

    class Meta:
        model = MuteRule
        fields = [
            "id",
            "name",
            "reason",
            "enabled",
        ]
        extra_kwargs = {
            "id": {"read_only": True},
            "name": {"required": False},
            "reason": {"required": False},
            "enabled": {"required": False},
        }

    def validate_name(self, value):
        """Validate that the name is unique within the tenant, excluding current instance."""
        tenant_id = self.context.get("tenant_id")
        if (
            MuteRule.objects.filter(tenant_id=tenant_id, name=value)
            .exclude(id=self.instance.id)
            .exists()
        ):
            raise ValidationError("A mute rule with this name already exists.")
        return value


# ThreatScore Snapshots


class ThreatScoreSnapshotSerializer(RLSSerializer):
    """
    Serializer for ThreatScore snapshots.
    Read-only serializer for retrieving historical ThreatScore metrics.
    """

    id = serializers.SerializerMethodField()

    class Meta:
        model = ThreatScoreSnapshot
        fields = [
            "id",
            "inserted_at",
            "scan",
            "provider",
            "compliance_id",
            "overall_score",
            "score_delta",
            "section_scores",
            "critical_requirements",
            "total_requirements",
            "passed_requirements",
            "failed_requirements",
            "manual_requirements",
            "total_findings",
            "passed_findings",
            "failed_findings",
        ]
        extra_kwargs = {
            "id": {"read_only": True},
            "inserted_at": {"read_only": True},
            "scan": {"read_only": True},
            "provider": {"read_only": True},
            "compliance_id": {"read_only": True},
            "overall_score": {"read_only": True},
            "score_delta": {"read_only": True},
            "section_scores": {"read_only": True},
            "critical_requirements": {"read_only": True},
            "total_requirements": {"read_only": True},
            "passed_requirements": {"read_only": True},
            "failed_requirements": {"read_only": True},
            "manual_requirements": {"read_only": True},
            "total_findings": {"read_only": True},
            "passed_findings": {"read_only": True},
            "failed_findings": {"read_only": True},
        }

    included_serializers = {
        "scan": "api.v1.serializers.ScanIncludeSerializer",
        "provider": "api.v1.serializers.ProviderIncludeSerializer",
    }

    def get_id(self, obj):
        if getattr(obj, "_aggregated", False):
            return "n/a"
        return str(obj.id)


# Resource Events Serializers


class ResourceEventSerializer(BaseSerializerV1):
    """Serializer for resource events (CloudTrail modification history).

    NOTE: drf-spectacular auto-generates fields[resource-events] sparse fieldsets
    parameter in the OpenAPI schema. This endpoint does not support sparse fieldsets.
    """

    id = serializers.CharField(source="event_id")
    event_time = serializers.DateTimeField()
    event_name = serializers.CharField()
    event_source = serializers.CharField()
    actor = serializers.CharField()
    actor_uid = serializers.CharField(allow_null=True, required=False)
    actor_type = serializers.CharField(allow_null=True, required=False)
    source_ip_address = serializers.CharField(allow_null=True, required=False)
    user_agent = serializers.CharField(allow_null=True, required=False)
    request_data = serializers.JSONField(allow_null=True, required=False)
    response_data = serializers.JSONField(allow_null=True, required=False)
    error_code = serializers.CharField(allow_null=True, required=False)
    error_message = serializers.CharField(allow_null=True, required=False)

    class Meta:
        resource_name = "resource-events"


# Finding Groups - Virtual aggregation entities


class FindingGroupSerializer(BaseSerializerV1):
    """
    Serializer for Finding Groups - aggregated findings by check_id.

    This is a non-model serializer since FindingGroup is a virtual entity
    created by aggregating the Finding model.
    """

    id = serializers.CharField(source="check_id")
    check_id = serializers.CharField()
    check_title = serializers.CharField(required=False, allow_null=True)
    check_description = serializers.CharField(required=False, allow_null=True)
    severity = serializers.CharField()
    status = serializers.CharField()
    impacted_providers = serializers.ListField(
        child=serializers.CharField(), required=False
    )
    resources_fail = serializers.IntegerField()
    resources_total = serializers.IntegerField()
    pass_count = serializers.IntegerField()
    fail_count = serializers.IntegerField()
    muted_count = serializers.IntegerField()
    new_count = serializers.IntegerField()
    changed_count = serializers.IntegerField()
    first_seen_at = serializers.DateTimeField(required=False, allow_null=True)
    last_seen_at = serializers.DateTimeField(required=False, allow_null=True)
    failing_since = serializers.DateTimeField(required=False, allow_null=True)

    class JSONAPIMeta:
        resource_name = "finding-groups"


class FindingGroupResourceSerializer(BaseSerializerV1):
    """
    Serializer for Finding Group Resources - resources within a finding group.

    Returns individual resources with their current status, severity,
    and timing information.
    """

    id = serializers.UUIDField(source="resource_id")
    resource = serializers.SerializerMethodField()
    provider = serializers.SerializerMethodField()
    status = serializers.CharField()
    severity = serializers.CharField()
    first_seen_at = serializers.DateTimeField(required=False, allow_null=True)
    last_seen_at = serializers.DateTimeField(required=False, allow_null=True)

    class JSONAPIMeta:
        resource_name = "finding-group-resources"

    @extend_schema_field(
        {
            "type": "object",
            "properties": {
                "uid": {"type": "string"},
                "name": {"type": "string"},
                "service": {"type": "string"},
                "region": {"type": "string"},
                "type": {"type": "string"},
            },
        }
    )
    def get_resource(self, obj):
        """Return nested resource object."""
        return {
            "uid": obj.get("resource_uid", ""),
            "name": obj.get("resource_name", ""),
            "service": obj.get("resource_service", ""),
            "region": obj.get("resource_region", ""),
            "type": obj.get("resource_type", ""),
        }

    @extend_schema_field(
        {
            "type": "object",
            "properties": {
                "type": {"type": "string"},
                "uid": {"type": "string"},
                "alias": {"type": "string"},
            },
        }
    )
    def get_provider(self, obj):
        """Return nested provider object."""
        return {
            "type": obj.get("provider_type", ""),
            "uid": obj.get("provider_uid", ""),
            "alias": obj.get("provider_alias", ""),
        }
