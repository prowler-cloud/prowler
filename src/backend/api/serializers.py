from rest_framework_json_api import serializers

from api.models import Tenant


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
