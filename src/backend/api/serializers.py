from rest_framework import serializers

from api.models import TestModel, Tenant


class TestModelSerializer(serializers.ModelSerializer):
    """To delete.

    Use this serializer for development/testing purposes.
    """

    class Meta:
        model = TestModel
        fields = "__all__"


class TenantSerializer(serializers.ModelSerializer):
    """
    Serializer for the Tenant model.
    """

    class Meta:
        model = Tenant
        fields = "__all__"
