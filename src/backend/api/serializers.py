from rest_framework_json_api import serializers

from api.models import Test
from api.rls import Tenant


class BaseSerializerV1(serializers.ModelSerializer):
    def get_root_meta(self, _resource, _many):
        return {"version": "v1"}


class TenantSerializer(BaseSerializerV1):
    """
    Serializer for the Tenant model.
    """

    class Meta:
        model = Tenant
        fields = "__all__"


class TestSerializer(BaseSerializerV1):
    tenant = serializers.PrimaryKeyRelatedField(
        queryset=Tenant.objects.all(), write_only=True
    )

    class Meta:
        model = Test
        fields = "__all__"

    def to_representation(self, instance):
        representation = super().to_representation(instance)
        representation.pop("tenant", None)
        return representation
