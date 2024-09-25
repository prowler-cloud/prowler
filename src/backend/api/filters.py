from datetime import date, datetime, timezone
from uuid import UUID

from django.conf import settings
from django.db.models import Q
from django_filters.rest_framework import (
    FilterSet,
    BooleanFilter,
    CharFilter,
    UUIDFilter,
    DateFilter,
)
from rest_framework_json_api.django_filters.backends import DjangoFilterBackend
from rest_framework_json_api.serializers import ValidationError

from api.db_utils import ProviderEnumField
from api.models import (
    Membership,
    Provider,
    Resource,
    ResourceTag,
    Scan,
    Task,
    StateChoices,
    Finding,
    SeverityChoices,
    StatusChoices,
)
from api.rls import Tenant
from api.uuid_utils import (
    datetime_to_uuid7,
    uuid7_start,
    uuid7_end,
    uuid7_range,
    parse_params_to_uuid7,
)
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
    if "__in" in lookup_field:
        values = value
        if isinstance(values, str):
            values = value.split(",")

        values = [v for v in values if v in enum_choices]
        return queryset.filter(**{lookup_field: values})

    if value not in enum_choices:
        raise ValidationError(
            f"Invalid provider value: '{value}'. Valid values are: "
            f"{', '.join(enum_choices)}"
        )

    return queryset.filter(**{lookup_field: value})


def extract_lookup_expr(name):
    """Extract the lookup expression from the filter name."""
    parts = name.split("__")
    return parts[-1] if len(parts) > 1 else "exact"


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


class MembershipFilter(FilterSet):
    date_joined = DateFilter(field_name="date_joined", lookup_expr="date")
    role = CharFilter(method="filter_role")

    def filter_role(self, queryset, name, value):
        return enum_filter(
            queryset,
            value,
            enum_choices=Membership.RoleChoices,
            lookup_field="role",
        )

    class Meta:
        model = Membership
        fields = {
            "tenant": ["exact"],
            "role": ["exact"],
            "date_joined": ["date", "gte", "lte"],
        }


class ProviderFilter(FilterSet):
    inserted_at = DateFilter(field_name="inserted_at", lookup_expr="date")
    updated_at = DateFilter(field_name="updated_at", lookup_expr="date")
    connected = BooleanFilter()
    provider = CharFilter(method="filter_provider_type")
    provider__in = CharFilter(method="filter_provider_type_in")

    def filter_provider_type(self, queryset, name, value):
        return enum_filter(
            queryset,
            value,
            enum_choices=Provider.ProviderChoices,
            lookup_field="provider",
        )

    def filter_provider_type_in(self, queryset, name, value):
        return enum_filter(
            queryset,
            value,
            enum_choices=Provider.ProviderChoices,
            lookup_field="provider__in",
        )

    class Meta:
        model = Provider
        fields = {
            "provider": ["exact", "in"],
            "id": ["exact", "in"],
            "uid": ["exact", "icontains", "in"],
            "alias": ["exact", "icontains", "in"],
            "inserted_at": ["gte", "lte"],
            "updated_at": ["gte", "lte"],
        }
        filter_overrides = {
            ProviderEnumField: {
                "filter_class": CharFilter,
            },
        }


class ProviderRelationshipFilterSet(FilterSet):
    provider_type = CharFilter(method="filter_provider_type")
    provider_type__in = CharFilter(method="filter_provider_type_in")
    provider_uid = CharFilter(method="filter_provider_uid")
    provider_uid__in = CharFilter(method="filter_provider_uid_in")
    provider_uid__icontains = CharFilter(method="filter_provider_uid_icontains")
    provider_alias = CharFilter(method="filter_provider_alias")
    provider_alias__in = CharFilter(method="filter_provider_alias_in")
    provider_alias__icontains = CharFilter(method="filter_provider_alias_icontains")

    # this can be overridden in subclasses
    provider_type_lookup_field = "provider__provider__exact"
    provider_type_in_lookup_field = "provider__provider__in"
    provider_uid_lookup_field = "provider__uid"
    provider_uid_in_lookup_field = "provider__uid__in"
    provider_uid_icontains_lookup_field = "provider__uid__icontains"
    provider_alias_lookup_field = "provider__alias"
    provider_alias_in_lookup_field = "provider__alias__in"
    provider_alias_icontains_lookup_field = "provider__alias__icontains"

    def filter_provider_type(self, queryset, name, value):
        return enum_filter(
            queryset,
            value,
            enum_choices=Provider.ProviderChoices,
            lookup_field=self.provider_type_lookup_field,
        )

    def filter_provider_type_in(self, queryset, name, value):
        if not isinstance(value, list):
            value = value.split(",")

        return enum_filter(
            queryset,
            value,
            enum_choices=Provider.ProviderChoices,
            lookup_field=self.provider_type_in_lookup_field,
        )

    def filter_provider_uid(self, queryset, name, value):
        return queryset.filter(**{self.provider_uid_lookup_field: value})

    def filter_provider_uid_in(self, queryset, name, value):
        if isinstance(value, str):
            value = value.split(",")
        return queryset.filter(**{self.provider_uid_in_lookup_field: value})

    def filter_provider_uid_icontains(self, queryset, name, value):
        return queryset.filter(**{self.provider_uid_icontains_lookup_field: value})

    def filter_provider_alias(self, queryset, name, value):
        return queryset.filter(**{self.provider_alias_lookup_field: value})

    def filter_provider_alias_in(self, queryset, name, value):
        if isinstance(value, str):
            value = value.split(",")
        return queryset.filter(**{self.provider_alias_in_lookup_field: value})

    def filter_provider_alias_icontains(self, queryset, name, value):
        return queryset.filter(**{self.provider_alias_icontains_lookup_field: value})


class ScanFilter(ProviderRelationshipFilterSet):
    inserted_at = DateFilter(field_name="inserted_at", lookup_expr="date")
    completed_at = DateFilter(field_name="completed_at", lookup_expr="date")
    started_at = DateFilter(field_name="started_at", lookup_expr="date")
    trigger = CharFilter(method="filter_trigger")

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
            "provider": ["exact", "in"],
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


class ResourceFilter(ProviderRelationshipFilterSet):
    tag_key = CharFilter(method="filter_tag_key")
    tag_value = CharFilter(method="filter_tag_value")
    tag = CharFilter(method="filter_tag")
    tags = CharFilter(method="filter_tag")
    inserted_at = DateFilter(field_name="inserted_at", lookup_expr="date")
    updated_at = DateFilter(field_name="updated_at", lookup_expr="date")

    class Meta:
        model = Resource
        fields = {
            "provider": ["exact", "in"],
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


class FindingFilter(ProviderRelationshipFilterSet):
    provider = UUIDFilter(field_name="scan__provider__id", lookup_expr="exact")
    provider__in = UUIDFilter(method="filter_provider_id_in")

    def filter_provider_id_in(self, queryset, name, value):
        if isinstance(value, str):
            value = value.split(",")
        if isinstance(value, UUID):
            value = [value]
        return queryset.filter(scan__provider__id__in=value)

    updated_at = DateFilter(field_name="updated_at", lookup_expr="date")

    delta = CharFilter(method="filter_delta")
    delta__in = CharFilter(method="filter_delta_in")
    status = CharFilter(method="filter_status")
    status__in = CharFilter(method="filter_status_in")
    severity = CharFilter(method="filter_severity")
    severity__in = CharFilter(method="filter_severity_in")
    impact = CharFilter(method="filter_severity")
    impact__in = CharFilter(method="filter_severity_in")

    resources = UUIDFilter(field_name="resource__id", lookup_expr="in")

    region = CharFilter(method="filter_region")
    region__in = CharFilter(method="filter_region_in")
    region__icontains = CharFilter(method="filter_region_icontains")

    service = CharFilter(method="filter_service")
    service__in = CharFilter(method="filter_service_in")
    service__icontains = CharFilter(method="filter_service_icontains")

    resource_uid = CharFilter(method="filter_resource_uid")
    resource_uid__in = CharFilter(method="filter_resource_uid_in")
    resource_uid__icontains = CharFilter(method="filter_resource_uid_icontains")

    resource_name = CharFilter(method="filter_resource_name")
    resource_name__in = CharFilter(method="filter_resource_name_in")
    resource_name__icontains = CharFilter(method="filter_resource_name_icontains")

    resource_type = CharFilter(method="filter_resource_type")
    resource_type__in = CharFilter(method="filter_resource_type_in")
    resource_type__icontains = CharFilter(method="filter_resource_type_icontains")

    scan = CharFilter(method="filter_scan_id")
    scan__in = CharFilter(method="filter_scan_id_in")

    inserted_at = DateFilter(method="filter_inserted_at", lookup_expr="date")
    inserted_at__date = DateFilter(method="filter_inserted_at", lookup_expr="date")
    inserted_at__gte = DateFilter(method="filter_inserted_at_gte")
    inserted_at__lte = DateFilter(method="filter_inserted_at_lte")

    class Meta:
        model = Finding
        fields = {
            "scan": ["exact", "in"],
            "check_id": ["exact", "in", "icontains"],
            "inserted_at": ["date", "gte", "lte"],
            "updated_at": ["gte", "lte"],
        }

    def __init__(self, *args, **kwargs):
        self.provider_type_lookup_field = "scan__provider__provider__exact"
        self.provider_type_in_lookup_field = "scan__provider__provider__in"
        self.provider_uid_lookup_field = "scan__provider__uid"
        self.provider_uid_in_lookup_field = "scan__provider__uid__in"
        self.provider_uid_icontains_lookup_field = "scan__provider__uid__icontains"
        self.provider_alias_lookup_field = "scan__provider__alias"
        self.provider_alias_in_lookup_field = "scan__provider__alias__in"
        self.provider_alias_icontains_lookup_field = "scan__provider__alias__icontains"
        super().__init__(*args, **kwargs)

        data = self.data
        if not data or (
            not data.get("scan")
            and not data.get("scan__in")
            and not data.get("inserted_at")
            and not data.get("inserted_at.date")
            and not data.get("inserted_at__gte")
            and not data.get("inserted_at__lte")
        ):
            self.add_default_filter()

    def add_default_filter(self):
        utc_now = datetime.now(timezone.utc)
        start = uuid7_start(datetime_to_uuid7(utc_now))

        self.queryset = self.queryset.filter(id__gte=start)

    def filter_delta(self, queryset, name, value):
        return enum_filter(
            queryset,
            value,
            enum_choices=Finding.DeltaChoices,
            lookup_field="delta",
        )

    def filter_delta_in(self, queryset, name, value):
        return enum_filter(
            queryset,
            value,
            enum_choices=Finding.DeltaChoices,
            lookup_field="delta__in",
        )

    def filter_severity(self, queryset, name, value):
        return enum_filter(
            queryset,
            value,
            enum_choices=SeverityChoices,
            lookup_field="severity",
        )

    def filter_severity_in(self, queryset, name, value):
        return enum_filter(
            queryset,
            value,
            enum_choices=SeverityChoices,
            lookup_field="severity__in",
        )

    def filter_status(self, queryset, name, value):
        return enum_filter(
            queryset,
            value,
            enum_choices=StatusChoices,
            lookup_field="status",
        )

    def filter_status_in(self, queryset, name, value):
        return enum_filter(
            queryset,
            value,
            enum_choices=StatusChoices,
            lookup_field="status__in",
        )

    def filter_region(self, queryset, name, value):
        return queryset.filter(resources__region=value)

    def filter_region_in(self, queryset, name, value):
        if isinstance(value, str):
            value = value.split(",")
        return queryset.filter(resources__region__in=value)

    def filter_region_icontains(self, queryset, name, value):
        return queryset.filter(resources__region__icontains=value)

    def filter_service(self, queryset, name, value):
        return queryset.filter(resources__service=value)

    def filter_service_in(self, queryset, name, value):
        if isinstance(value, str):
            value = value.split(",")
        return queryset.filter(resources__service__in=value)

    def filter_service_icontains(self, queryset, name, value):
        return queryset.filter(resources__service__icontains=value)

    def filter_resource_uid(self, queryset, name, value):
        return queryset.filter(resources__uid=value)

    def filter_resource_uid_in(self, queryset, name, value):
        if isinstance(value, str):
            value = value.split(",")
        return queryset.filter(resources__uid__in=value)

    def filter_resource_uid_icontains(self, queryset, name, value):
        return queryset.filter(resources__uid__icontains=value)

    def filter_resource_name(self, queryset, name, value):
        return queryset.filter(resources__name=value)

    def filter_resource_name_in(self, queryset, name, value):
        if isinstance(value, str):
            value = value.split(",")
        return queryset.filter(resources__name__in=value)

    def filter_resource_name_icontains(self, queryset, name, value):
        return queryset.filter(resources__name__icontains=value)

    def filter_resource_type(self, queryset, name, value):
        return queryset.filter(resources__type=value)

    def filter_resource_type_in(self, queryset, name, value):
        if isinstance(value, str):
            value = value.split(",")
        return queryset.filter(resources__type__in=value)

    def filter_resource_type_icontains(self, queryset, name, value):
        return queryset.filter(resources__type__icontains=value)

    #  Convert filter values to UUIDv7 values for use with partitioning

    def filter_scan_id(self, queryset, name, value):
        value = parse_params_to_uuid7(value)

        start = uuid7_start(value)
        end = uuid7_end(value, settings.FINDINGS_TABLE_PARTITION_DAYS)
        return queryset.filter(id__gte=start).filter(id__lt=end).filter(scan__id=value)

    def filter_scan_id_in(self, queryset, name, value):
        value = parse_params_to_uuid7(value)
        if isinstance(value, UUID):
            value = [value]

        start, end = uuid7_range(value)
        if start == end:
            return queryset.filter(id__gte=start).filter(scan__id__in=value)
        else:
            return (
                queryset.filter(id__gte=start)
                .filter(id__lt=end)
                .filter(scan__id__in=value)
            )

    def filter_inserted_at(self, queryset, name, value):
        value = self.maybe_date_to_datetime(value)
        start = uuid7_start(datetime_to_uuid7(value))

        return queryset.filter(id__gte=start).filter(inserted_at=value)

    def filter_inserted_at_gte(self, queryset, name, value):
        value = self.maybe_date_to_datetime(value)
        start = uuid7_start(datetime_to_uuid7(value))

        return queryset.filter(id__gte=start).filter(inserted_at__gte=value)

    def filter_inserted_at_lte(self, queryset, name, value):
        value = self.maybe_date_to_datetime(value)
        end = uuid7_start(datetime_to_uuid7(value))

        return queryset.filter(id__lte=end).filter(inserted_at__lte=value)

    @staticmethod
    def maybe_date_to_datetime(value):
        dt = value
        if isinstance(value, date):
            dt = datetime.combine(value, datetime.min.time(), tzinfo=timezone.utc)
        return dt
