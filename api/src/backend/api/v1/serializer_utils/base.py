import yaml
from rest_framework_json_api import serializers
from rest_framework_json_api.serializers import ValidationError


class BaseValidateSerializer(serializers.Serializer):
    def validate(self, data):
        if hasattr(self, "initial_data"):
            initial_data = set(self.initial_data.keys()) - {"id", "type"}
            unknown_keys = initial_data - set(self.fields.keys())
            if unknown_keys:
                raise ValidationError(f"Invalid fields: {unknown_keys}")
        return data


class YamlOrJsonField(serializers.JSONField):
    def to_internal_value(self, data):
        if isinstance(data, str):
            try:
                data = yaml.safe_load(data)
            except yaml.YAMLError as exc:
                raise serializers.ValidationError("Invalid YAML format") from exc
        return super().to_internal_value(data)
