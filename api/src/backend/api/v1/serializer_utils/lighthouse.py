import re

from rest_framework_json_api import serializers


class OpenAICredentialsSerializer(serializers.Serializer):
    api_key = serializers.CharField()

    def validate_api_key(self, value: str) -> str:
        pattern = r"^sk-[\w-]+$"
        if not re.match(pattern, value or ""):
            raise serializers.ValidationError("Invalid OpenAI API key format.")
        return value
