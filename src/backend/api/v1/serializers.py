import json

from drf_spectacular.utils import extend_schema_field
from rest_framework_json_api import serializers
from rest_framework_json_api.serializers import ValidationError

from api.models import StateChoices, Provider, Scan, Task, Resource, ResourceTag
from api.rls import Tenant
from api.utils import merge_dicts


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


# Tasks
class TaskBase(serializers.Serializer):
    state_mapping = {
        "PENDING": StateChoices.SCHEDULED,
        "STARTED": StateChoices.EXECUTING,
        "PROGRESS": StateChoices.EXECUTING,
        "SUCCESS": StateChoices.COMPLETED,
        "FAILURE": StateChoices.FAILED,
        "REVOKED": StateChoices.CANCELLED,
    }

    class JSONAPIMeta:
        resource_name = "Task"

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


class DelayedTaskSerializer(TaskBase):
    id = serializers.CharField()
    state = serializers.SerializerMethodField(read_only=True)

    class Meta:
        fields = [
            "id",
            "state",
        ]

    @extend_schema_field(
        {
            "type": "string",
            "enum": StateChoices.values,
        }
    )
    def get_state(self, obj):
        task_result_state = obj.status if obj else None
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
            task_args = json.loads(task_args.replace("'", '"'))
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

    class Meta:
        model = Tenant
        fields = "__all__"


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
            "started_at",
            "completed_at",
            "scheduled_at",
            "url",
        ]


class ScanCreateSerializer(RLSSerializer, BaseWriteSerializer):
    class Meta:
        model = Scan
        # TODO: add mutelist when implemented
        fields = ["provider", "scanner_args", "name"]

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


class ResourceTagSerializer(RLSSerializer):
    """
    Serializer fore the ResourceTag model
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
        ]
        extra_kwargs = {
            "id": {"read_only": True},
            "inserted_at": {"read_only": True},
            "updated_at": {"read_only": True},
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
