from django.db.models import Q
from django_filters.rest_framework import (
    FilterSet,
    BooleanFilter,
    CharFilter,
    DateFilter,
)
from rest_framework_json_api.django_filters.backends import DjangoFilterBackend
from rest_framework_json_api.serializers import ValidationError

from api.db_utils import ProviderEnumField
from api.models import Provider, Resource, ResourceTag, Scan, Task, StateChoices
from api.rls import Tenant
from api.v1.serializers import TaskBase


def enum_filter(queryset, value, enum_choices, lookup_field: str):
    """
    Filter a queryset based on a provided value, using a specified lookup field
    and validating against a given enumeration.

    This function filters a given queryset by checking if the provided `value`
    matches a valid choice in the specified `enum_choices` (a Django `TextChoices` enum).
    If the `value` is valid, the queryset is filtered using the specified `lookup_field`.
    Otherwise, a `ValidationError` is raised.

    Args:
        queryset (QuerySet): The Django queryset to be filtered.
        value (str): The value to filter the queryset by, which must be a valid
                     option in the specified `enum_choices`.
        enum_choices: The enumeration class that defines the valid
                                    choices for the `value`.
        lookup_field (str): The field or lookup path within the model used for
                            filtering the queryset.

    Returns:
        QuerySet: A filtered queryset based on the provided `value` and `lookup_field`.

    Raises:
        ValidationError: If the provided `value` is not a valid choice in
                         the specified `enum_choices`.
    """
    if value not in enum_choices:
        raise ValidationError(
            f"Invalid provider value: '{value}'. Valid values are: "
            f"{', '.join(enum_choices)}"
        )

    return queryset.filter(**{lookup_field: value})


class CustomDjangoFilterBackend(DjangoFilterBackend):
    def to_html(self, _request, _queryset, _view):
        """Override this method to use the Browsable API in dev environments.

        This disables the HTML render for the default filter.
        """
        return None


class TenantFilter(FilterSet):
    inserted_at = DateFilter(field_name="inserted_at", lookup_expr="date")
    updated_at = DateFilter(field_name="updated_at", lookup_expr="date")

    class Meta:
        model = Tenant
        fields = {
            "name": ["exact", "icontains"],
            "inserted_at": ["date", "gte", "lte"],
            "updated_at": ["gte", "lte"],
        }


class ProviderFilter(FilterSet):
    inserted_at = DateFilter(field_name="inserted_at", lookup_expr="date")
    updated_at = DateFilter(field_name="updated_at", lookup_expr="date")
    connected = BooleanFilter()
    provider = CharFilter(method="filter_provider")

    def filter_provider(self, queryset, name, value):
        return enum_filter(
            queryset,
            value,
            enum_choices=Provider.ProviderChoices,
            lookup_field="provider",
        )

    class Meta:
        model = Provider
        fields = {
            "provider": ["exact"],
            "provider_id": ["exact", "icontains"],
            "alias": ["exact", "icontains"],
            "inserted_at": ["gte", "lte"],
            "updated_at": ["gte", "lte"],
        }
        filter_overrides = {
            ProviderEnumField: {
                "filter_class": CharFilter,
            },
        }


class ScanFilter(FilterSet):
    inserted_at = DateFilter(field_name="inserted_at", lookup_expr="date")
    completed_at = DateFilter(field_name="completed_at", lookup_expr="date")
    started_at = DateFilter(field_name="started_at", lookup_expr="date")
    provider = CharFilter(method="filter_provider")
    trigger = CharFilter(method="filter_trigger")

    def filter_provider(self, queryset, name, value):
        return enum_filter(
            queryset,
            value,
            enum_choices=Provider.ProviderChoices,
            lookup_field="provider__provider",
        )

    def filter_trigger(self, queryset, name, value):
        if value not in Scan.TriggerChoices:
            raise ValidationError(
                f"Invalid scan trigger value: '{value}'. Valid values are: "
                f"{', '.join(Scan.TriggerChoices)}"
            )

        return queryset.filter(trigger=value)

    class Meta:
        model = Scan
        fields = {
            "provider": ["exact"],
            "provider_id": ["exact", "in"],
            "name": ["exact", "icontains"],
            "started_at": ["gte", "lte"],
            "trigger": ["exact"],
        }


class TaskFilter(FilterSet):
    name = CharFilter(field_name="task_runner_task__task_name", lookup_expr="exact")
    name__icontains = CharFilter(
        field_name="task_runner_task__task_name", lookup_expr="icontains"
    )
    state = CharFilter(method="filter_state", lookup_expr="exact")

    task_state_inverse_mapping_values = {
        v: k for k, v in TaskBase.state_mapping.items()
    }

    def filter_state(self, queryset, name, value):
        if value not in StateChoices:
            raise ValidationError(
                f"Invalid provider value: '{value}'. Valid values are: "
                f"{', '.join(StateChoices)}"
            )

        return queryset.filter(
            task_runner_task__status=self.task_state_inverse_mapping_values[value]
        )

    class Meta:
        model = Task
        fields = []


class ResourceTagFilter(FilterSet):
    class Meta:
        model = ResourceTag
        fields = {
            "key": ["exact", "icontains"],
            "value": ["exact", "icontains"],
        }
        search = ["text_search"]


class ResourceFilter(FilterSet):
    provider = CharFilter(method="filter_provider")
    tag_key = CharFilter(method="filter_tag_key")
    tag_value = CharFilter(method="filter_tag_value")
    tag = CharFilter(method="filter_tag")
    tags = CharFilter(method="filter_tag")
    inserted_at = DateFilter(field_name="inserted_at", lookup_expr="date")
    updated_at = DateFilter(field_name="updated_at", lookup_expr="date")

    def filter_provider(self, queryset, name, value):
        return enum_filter(
            queryset,
            value,
            enum_choices=Provider.ProviderChoices,
            lookup_field="provider__provider",
        )

    class Meta:
        model = Resource
        fields = {
            "provider_id": ["exact", "in"],
            "uid": ["exact", "icontains"],
            "name": ["exact", "icontains"],
            "region": ["exact", "icontains", "in"],
            "service": ["exact", "icontains", "in"],
            "type": ["exact", "icontains", "in"],
            "inserted_at": ["gte", "lte"],
            "updated_at": ["gte", "lte"],
        }

    def filter_tag_key(self, queryset, name, value):
        return queryset.filter(Q(tags__key=value) | Q(tags__key__icontains=value))

    def filter_tag_value(self, queryset, name, value):
        return queryset.filter(Q(tags__value=value) | Q(tags__value__icontains=value))

    def filter_tag(self, queryset, name, value):
        # we won't know what the user wants to filter on just based on the value
        # and we don't want to build special filtering logic for every possible
        # provider tag spec, so we'll just do a full text search
        return queryset.filter(tags__text_search=value)
