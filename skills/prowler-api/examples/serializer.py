# Example: RLSSerializer with Relationships
# Source: api/src/backend/api/v1/serializers.py

from rest_framework_json_api import serializers

from api.models import Provider, ProviderGroup, ProviderGroupMembership, Role


class RLSSerializer(BaseModelSerializerV1):
    """
    Base serializer that auto-injects tenant_id from context on create.

    Key pattern: tenant_id comes from ViewSet context, not from request body.
    """

    def create(self, validated_data):
        tenant_id = self.context.get("tenant_id")
        validated_data["tenant_id"] = tenant_id
        return super().create(validated_data)


class ProviderGroupSerializer(RLSSerializer, BaseWriteSerializer):
    """
    Example serializer with ResourceRelatedField for relationships.

    Key patterns:
    1. Use ResourceRelatedField for JSON:API relationships
    2. Custom validation in validate() method
    3. read_only fields in extra_kwargs
    """

    providers = serializers.ResourceRelatedField(
        queryset=Provider.objects.all(), many=True, required=False
    )
    roles = serializers.ResourceRelatedField(
        queryset=Role.objects.all(), many=True, required=False
    )

    def validate(self, attrs):
        """Custom validation - check for unique name."""
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


class ProviderGroupCreateSerializer(ProviderGroupSerializer):
    """
    Create serializer with many-to-many relationship handling.

    Key pattern: Pop relationships, create main object, then bulk_create through models.
    """

    def create(self, validated_data):
        # Pop relationship data before creating main object
        providers = validated_data.pop("providers", [])
        roles = validated_data.pop("roles", [])
        tenant_id = self.context.get("tenant_id")

        # Create main object
        provider_group = ProviderGroup.objects.create(
            tenant_id=tenant_id, **validated_data
        )

        # Bulk create through model instances for providers
        through_model_instances = [
            ProviderGroupMembership(
                provider_group=provider_group,
                provider=provider,
                tenant_id=tenant_id,
            )
            for provider in providers
        ]
        ProviderGroupMembership.objects.bulk_create(through_model_instances)

        # Bulk create through model instances for roles
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
