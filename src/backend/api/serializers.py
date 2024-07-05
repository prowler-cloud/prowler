from rest_framework import serializers

from api.models import TestModel


class TestModelSerializer(serializers.ModelSerializer):
    """To delete.

    Use this serializer for development/testing purposes.
    """

    class Meta:
        model = TestModel
        fields = "__all__"
