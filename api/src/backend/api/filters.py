from datetime import date, datetime, timedelta, timezone

from dateutil.parser import parse
from django.conf import settings
from django.db.models import F, Q
from django_filters.rest_framework import (
    BaseInFilter,
    BooleanFilter,
    CharFilter,
    ChoiceFilter,
    DateFilter,
    FilterSet,
    UUIDFilter,
)
from rest_framework_json_api.django_filters.backends import DjangoFilterBackend
from rest_framework_json_api.serializers import ValidationError

from api.db_utils import (
    FindingDeltaEnumField,
    InvitationStateEnumField,
    ProviderEnumField,
    SeverityEnumField,
    StatusEnumField,
)
from api.models import (
    AttackPathsScan,
    AttackSurfaceOverview,
    ComplianceRequirementOverview,
    DailySeveritySummary,
    Finding,
    FindingGroupDailySummary,
    Integration,
    Invitation,
    LighthouseProviderConfiguration,
    LighthouseProviderModels,
    Membership,
    MuteRule,
    OverviewStatusChoices,
    PermissionChoices,
    Processor,
    Provider,
    ProviderComplianceScore,
    ProviderGroup,
    ProviderSecret,
    Resource,
    ResourceTag,
    Role,
    Scan,
    ScanCategorySummary,
    ScanGroupSummary,
    ScanSummary,
    SeverityChoices,
    StateChoices,
    StatusChoices,
    Task,
    TenantAPIKey,
    ThreatScoreSnapshot,
    User,
)
from api.rls import Tenant
from api.uuid_utils import (
    datetime_to_uuid7,
    transform_into_uuid7,
    uuid7_end,
    uuid7_range,
    uuid7_start,
)
from api.v1.serializers import TaskBase


class CustomDjangoFilterBackend(DjangoFilterBackend):
    def to_html(self, _request, _queryset, _view):
        """Override this method to use the Browsable API in dev environments.

        This disables the HTML render for the default filter.
        """
        return None

    def get_filterset_class(self, view, queryset=None):
        # Check if the view has 'get_filterset_class' method
        if hasattr(view, "get_filterset_class"):
            return view.get_filterset_class()
        # Fallback to the default implementation
        return super().get_filterset_class(view, queryset)


class UUIDInFilter(BaseInFilter, UUIDFilter):
    pass


class CharInFilter(BaseInFilter, CharFilter):
    pass


class ChoiceInFilter(BaseInFilter, ChoiceFilter):
    pass


class BaseProviderFilter(FilterSet):
    """
    Abstract base filter for models with direct FK to Provider.

    Provides standard provider_id and provider_type filters.
    Subclasses must define Meta.model.
    """

    provider_id = UUIDFilter(field_name="provider__id", lookup_expr="exact")
    provider_id__in = UUIDInFilter(field_name="provider__id", lookup_expr="in")
    provider_type = ChoiceFilter(
        field_name="provider__provider", choices=Provider.ProviderChoices.choices
    )
    provider_type__in = ChoiceInFilter(
        field_name="provider__provider",
        choices=Provider.ProviderChoices.choices,
        lookup_expr="in",
    )

    class Meta:
        abstract = True
        fields = {}


class BaseScanProviderFilter(FilterSet):
    """
    Abstract base filter for models with FK to Scan (and Scan has FK to Provider).

    Provides standard provider_id and provider_type filters via scan relationship.
    Subclasses must define Meta.model.
    """

    provider_id = UUIDFilter(field_name="scan__provider__id", lookup_expr="exact")
    provider_id__in = UUIDInFilter(field_name="scan__provider__id", lookup_expr="in")
    provider_type = ChoiceFilter(
        field_name="scan__provider__provider", choices=Provider.ProviderChoices.choices
    )
    provider_type__in = ChoiceInFilter(
        field_name="scan__provider__provider",
        choices=Provider.ProviderChoices.choices,
        lookup_expr="in",
    )

    class Meta:
        abstract = True
        fields = {}


class CommonFindingFilters(FilterSet):
    # We filter providers from the scan in findings
    # Both 'provider' and 'provider_id' parameters are supported for API consistency
    # Frontend uses 'provider_id' uniformly across all endpoints
    provider = UUIDFilter(field_name="scan__provider__id", lookup_expr="exact")
    provider__in = UUIDInFilter(field_name="scan__provider__id", lookup_expr="in")
    provider_id = UUIDFilter(field_name="scan__provider__id", lookup_expr="exact")
    provider_id__in = UUIDInFilter(field_name="scan__provider__id", lookup_expr="in")
    provider_type = ChoiceFilter(
        choices=Provider.ProviderChoices.choices, field_name="scan__provider__provider"
    )
    provider_type__in = ChoiceInFilter(
        choices=Provider.ProviderChoices.choices, field_name="scan__provider__provider"
    )
    provider_uid = CharFilter(field_name="scan__provider__uid", lookup_expr="exact")
    provider_uid__in = CharInFilter(field_name="scan__provider__uid", lookup_expr="in")
    provider_uid__icontains = CharFilter(
        field_name="scan__provider__uid", lookup_expr="icontains"
    )
    provider_alias = CharFilter(field_name="scan__provider__alias", lookup_expr="exact")
    provider_alias__in = CharInFilter(
        field_name="scan__provider__alias", lookup_expr="in"
    )
    provider_alias__icontains = CharFilter(
        field_name="scan__provider__alias", lookup_expr="icontains"
    )

    updated_at = DateFilter(field_name="updated_at", lookup_expr="date")

    uid = CharFilter(field_name="uid")
    delta = ChoiceFilter(choices=Finding.DeltaChoices.choices)
    status = ChoiceFilter(choices=StatusChoices.choices)
    severity = ChoiceFilter(choices=SeverityChoices)
    impact = ChoiceFilter(choices=SeverityChoices)
    muted = BooleanFilter(
        help_text="If this filter is not provided, muted and non-muted findings will be returned."
    )

    resources = UUIDInFilter(field_name="resources__id", lookup_expr="in")

    region = CharFilter(method="filter_resource_region")
    region__in = CharInFilter(field_name="resource_regions", lookup_expr="overlap")
    region__icontains = CharFilter(
        field_name="resource_regions", lookup_expr="icontains"
    )

    service = CharFilter(method="filter_resource_service")
    service__in = CharInFilter(field_name="resource_services", lookup_expr="overlap")
    service__icontains = CharFilter(
        field_name="resource_services", lookup_expr="icontains"
    )

    resource_uid = CharFilter(field_name="resources__uid")
    resource_uid__in = CharInFilter(field_name="resources__uid", lookup_expr="in")
    resource_uid__icontains = CharFilter(
        field_name="resources__uid", lookup_expr="icontains"
    )

    resource_name = CharFilter(field_name="resources__name")
    resource_name__in = CharInFilter(field_name="resources__name", lookup_expr="in")
    resource_name__icontains = CharFilter(
        field_name="resources__name", lookup_expr="icontains"
    )

    resource_type = CharFilter(method="filter_resource_type")
    resource_type__in = CharInFilter(field_name="resource_types", lookup_expr="overlap")
    resource_type__icontains = CharFilter(
        field_name="resources__type", lookup_expr="icontains"
    )

    category = CharFilter(method="filter_category")
    category__in = CharInFilter(field_name="categories", lookup_expr="overlap")

    resource_groups = CharFilter(field_name="resource_groups", lookup_expr="exact")
    resource_groups__in = CharInFilter(field_name="resource_groups", lookup_expr="in")

    # Temporarily disabled until we implement tag filtering in the UI
    # resource_tag_key = CharFilter(field_name="resources__tags__key")
    # resource_tag_key__in = CharInFilter(
    #     field_name="resources__tags__key", lookup_expr="in"
    # )
    # resource_tag_key__icontains = CharFilter(
    #     field_name="resources__tags__key", lookup_expr="icontains"
    # )
    # resource_tag_value = CharFilter(field_name="resources__tags__value")
    # resource_tag_value__in = CharInFilter(
    #     field_name="resources__tags__value", lookup_expr="in"
    # )
    # resource_tag_value__icontains = CharFilter(
    #     field_name="resources__tags__value", lookup_expr="icontains"
    # )
    # resource_tags = CharInFilter(
    #     method="filter_resource_tag",
    #     lookup_expr="in",
    #     help_text="Filter by resource tags `key:value` pairs.\nMultiple values may be "
    #     "separated by commas.",
    # )

    def filter_resource_service(self, queryset, name, value):
        return queryset.filter(resource_services__contains=[value])

    def filter_resource_region(self, queryset, name, value):
        return queryset.filter(resource_regions__contains=[value])

    def filter_resource_type(self, queryset, name, value):
        return queryset.filter(resource_types__contains=[value])

    def filter_category(self, queryset, name, value):
        return queryset.filter(categories__contains=[value])

    def filter_resource_tag(self, queryset, name, value):
        overall_query = Q()
        for key_value_pair in value:
            tag_key, tag_value = key_value_pair.split(":", 1)
            overall_query |= Q(
                resources__tags__key__icontains=tag_key,
                resources__tags__value__icontains=tag_value,
            )
        return queryset.filter(overall_query).distinct()


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
    role = ChoiceFilter(choices=Membership.RoleChoices.choices)

    class Meta:
        model = Membership
        fields = {
            "tenant": ["exact"],
            "role": ["exact"],
            "date_joined": ["date", "gte", "lte"],
        }


class ProviderFilter(FilterSet):
    inserted_at = DateFilter(
        field_name="inserted_at",
        lookup_expr="date",
        help_text="""Filter by date when the provider was added
        (format: YYYY-MM-DD)""",
    )
    updated_at = DateFilter(
        field_name="updated_at",
        lookup_expr="date",
        help_text="""Filter by date when the provider was updated
        (format: YYYY-MM-DD)""",
    )
    connected = BooleanFilter(
        help_text="""Filter by connection status. Set to True to return only
        connected providers, or False to return only providers with failed
        connections. If not specified, both connected and failed providers are
        included. Providers with no connection attempt (status is null) are
        excluded from this filter."""
    )
    provider = ChoiceFilter(choices=Provider.ProviderChoices.choices)
    provider__in = ChoiceInFilter(
        field_name="provider",
        choices=Provider.ProviderChoices.choices,
        lookup_expr="in",
    )
    provider_type = ChoiceFilter(
        choices=Provider.ProviderChoices.choices, field_name="provider"
    )
    provider_type__in = ChoiceInFilter(
        field_name="provider",
        choices=Provider.ProviderChoices.choices,
        lookup_expr="in",
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
    provider_type = ChoiceFilter(
        choices=Provider.ProviderChoices.choices, field_name="provider__provider"
    )
    provider_type__in = ChoiceInFilter(
        choices=Provider.ProviderChoices.choices, field_name="provider__provider"
    )
    provider_uid = CharFilter(field_name="provider__uid", lookup_expr="exact")
    provider_uid__in = CharInFilter(field_name="provider__uid", lookup_expr="in")
    provider_uid__icontains = CharFilter(
        field_name="provider__uid", lookup_expr="icontains"
    )
    provider_alias = CharFilter(field_name="provider__alias", lookup_expr="exact")
    provider_alias__in = CharInFilter(field_name="provider__alias", lookup_expr="in")
    provider_alias__icontains = CharFilter(
        field_name="provider__alias", lookup_expr="icontains"
    )


class ProviderGroupFilter(FilterSet):
    inserted_at = DateFilter(field_name="inserted_at", lookup_expr="date")
    updated_at = DateFilter(field_name="updated_at", lookup_expr="date")

    class Meta:
        model = ProviderGroup
        fields = {
            "id": ["exact", "in"],
            "name": ["exact", "in"],
            "inserted_at": ["gte", "lte"],
            "updated_at": ["gte", "lte"],
        }


class ScanFilter(ProviderRelationshipFilterSet):
    inserted_at = DateFilter(field_name="inserted_at", lookup_expr="date")
    completed_at = DateFilter(field_name="completed_at", lookup_expr="date")
    started_at = DateFilter(field_name="started_at", lookup_expr="date")
    next_scan_at = DateFilter(field_name="next_scan_at", lookup_expr="date")
    trigger = ChoiceFilter(choices=Scan.TriggerChoices.choices)
    state = ChoiceFilter(choices=StateChoices.choices)
    state__in = ChoiceInFilter(
        field_name="state", choices=StateChoices.choices, lookup_expr="in"
    )

    class Meta:
        model = Scan
        fields = {
            "provider": ["exact", "in"],
            "name": ["exact", "icontains"],
            "started_at": ["gte", "lte"],
            "next_scan_at": ["gte", "lte"],
            "trigger": ["exact"],
        }


class AttackPathsScanFilter(ProviderRelationshipFilterSet):
    inserted_at = DateFilter(field_name="inserted_at", lookup_expr="date")
    completed_at = DateFilter(field_name="completed_at", lookup_expr="date")
    started_at = DateFilter(field_name="started_at", lookup_expr="date")
    state = ChoiceFilter(choices=StateChoices.choices)
    state__in = ChoiceInFilter(
        field_name="state", choices=StateChoices.choices, lookup_expr="in"
    )

    class Meta:
        model = AttackPathsScan
        fields = {
            "provider": ["exact", "in"],
            "scan": ["exact", "in"],
        }


class TaskFilter(FilterSet):
    name = CharFilter(field_name="task_runner_task__task_name", lookup_expr="exact")
    name__icontains = CharFilter(
        field_name="task_runner_task__task_name", lookup_expr="icontains"
    )
    state = ChoiceFilter(
        choices=StateChoices.choices, method="filter_state", lookup_expr="exact"
    )
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
    provider_id = UUIDFilter(field_name="provider__id", lookup_expr="exact")
    provider_id__in = UUIDInFilter(field_name="provider__id", lookup_expr="in")
    tag_key = CharFilter(method="filter_tag_key")
    tag_value = CharFilter(method="filter_tag_value")
    tag = CharFilter(method="filter_tag")
    tags = CharFilter(method="filter_tag")
    inserted_at = DateFilter(field_name="inserted_at", lookup_expr="date")
    updated_at = DateFilter(field_name="updated_at", lookup_expr="date")
    scan = UUIDFilter(field_name="provider__scan", lookup_expr="exact")
    scan__in = UUIDInFilter(field_name="provider__scan", lookup_expr="in")
    groups = CharFilter(method="filter_groups")
    groups__in = CharInFilter(field_name="groups", lookup_expr="overlap")

    class Meta:
        model = Resource
        fields = {
            "id": ["exact", "in"],
            "provider": ["exact", "in"],
            "uid": ["exact", "icontains", "in"],
            "name": ["exact", "icontains", "in"],
            "region": ["exact", "icontains", "in"],
            "service": ["exact", "icontains", "in"],
            "type": ["exact", "icontains", "in"],
            "inserted_at": ["gte", "lte"],
            "updated_at": ["gte", "lte"],
        }

    def filter_groups(self, queryset, name, value):
        return queryset.filter(groups__contains=[value])

    def filter_queryset(self, queryset):
        if not (self.data.get("scan") or self.data.get("scan__in")) and not (
            self.data.get("updated_at")
            or self.data.get("updated_at__date")
            or self.data.get("updated_at__gte")
            or self.data.get("updated_at__lte")
        ):
            raise ValidationError(
                [
                    {
                        "detail": "At least one date filter is required: filter[updated_at], filter[updated_at.gte], "
                        "or filter[updated_at.lte].",
                        "status": 400,
                        "source": {"pointer": "/data/attributes/updated_at"},
                        "code": "required",
                    }
                ]
            )

        gte_date = (
            parse(self.data.get("updated_at__gte")).date()
            if self.data.get("updated_at__gte")
            else datetime.now(timezone.utc).date()
        )
        lte_date = (
            parse(self.data.get("updated_at__lte")).date()
            if self.data.get("updated_at__lte")
            else datetime.now(timezone.utc).date()
        )

        if abs(lte_date - gte_date) > timedelta(
            days=settings.FINDINGS_MAX_DAYS_IN_RANGE
        ):
            raise ValidationError(
                [
                    {
                        "detail": f"The date range cannot exceed {settings.FINDINGS_MAX_DAYS_IN_RANGE} days.",
                        "status": 400,
                        "source": {"pointer": "/data/attributes/updated_at"},
                        "code": "invalid",
                    }
                ]
            )

        return super().filter_queryset(queryset)

    def filter_tag_key(self, queryset, name, value):
        return queryset.filter(Q(tags__key=value) | Q(tags__key__icontains=value))

    def filter_tag_value(self, queryset, name, value):
        return queryset.filter(Q(tags__value=value) | Q(tags__value__icontains=value))

    def filter_tag(self, queryset, name, value):
        # We won't know what the user wants to filter on just based on the value,
        # and we don't want to build special filtering logic for every possible
        # provider tag spec, so we'll just do a full text search
        return queryset.filter(tags__text_search=value)


class LatestResourceFilter(ProviderRelationshipFilterSet):
    provider_id = UUIDFilter(field_name="provider__id", lookup_expr="exact")
    provider_id__in = UUIDInFilter(field_name="provider__id", lookup_expr="in")
    tag_key = CharFilter(method="filter_tag_key")
    tag_value = CharFilter(method="filter_tag_value")
    tag = CharFilter(method="filter_tag")
    tags = CharFilter(method="filter_tag")
    groups = CharFilter(method="filter_groups")
    groups__in = CharInFilter(field_name="groups", lookup_expr="overlap")

    class Meta:
        model = Resource
        fields = {
            "id": ["exact", "in"],
            "provider": ["exact", "in"],
            "uid": ["exact", "icontains", "in"],
            "name": ["exact", "icontains", "in"],
            "region": ["exact", "icontains", "in"],
            "service": ["exact", "icontains", "in"],
            "type": ["exact", "icontains", "in"],
        }

    def filter_groups(self, queryset, name, value):
        return queryset.filter(groups__contains=[value])

    def filter_tag_key(self, queryset, name, value):
        return queryset.filter(Q(tags__key=value) | Q(tags__key__icontains=value))

    def filter_tag_value(self, queryset, name, value):
        return queryset.filter(Q(tags__value=value) | Q(tags__value__icontains=value))

    def filter_tag(self, queryset, name, value):
        # We won't know what the user wants to filter on just based on the value,
        # and we don't want to build special filtering logic for every possible
        # provider tag spec, so we'll just do a full text search
        return queryset.filter(tags__text_search=value)


class FindingFilter(CommonFindingFilters):
    scan = UUIDFilter(method="filter_scan_id")
    scan__in = UUIDInFilter(method="filter_scan_id_in")

    inserted_at = DateFilter(method="filter_inserted_at", lookup_expr="date")
    inserted_at__date = DateFilter(method="filter_inserted_at", lookup_expr="date")
    inserted_at__gte = DateFilter(
        method="filter_inserted_at_gte",
        help_text=f"Maximum date range is {settings.FINDINGS_MAX_DAYS_IN_RANGE} days.",
    )
    inserted_at__lte = DateFilter(
        method="filter_inserted_at_lte",
        help_text=f"Maximum date range is {settings.FINDINGS_MAX_DAYS_IN_RANGE} days.",
    )

    class Meta:
        model = Finding
        fields = {
            "id": ["exact", "in"],
            "uid": ["exact", "in"],
            "scan": ["exact", "in"],
            "delta": ["exact", "in"],
            "status": ["exact", "in"],
            "severity": ["exact", "in"],
            "impact": ["exact", "in"],
            "check_id": ["exact", "in", "icontains"],
            "inserted_at": ["date", "gte", "lte"],
            "updated_at": ["gte", "lte"],
        }
        filter_overrides = {
            FindingDeltaEnumField: {
                "filter_class": CharFilter,
            },
            StatusEnumField: {
                "filter_class": CharFilter,
            },
            SeverityEnumField: {
                "filter_class": CharFilter,
            },
        }

    def filter_resource_type(self, queryset, name, value):
        return queryset.filter(resource_types__contains=[value])

    def filter_resource_region(self, queryset, name, value):
        return queryset.filter(resource_regions__contains=[value])

    def filter_resource_service(self, queryset, name, value):
        return queryset.filter(resource_services__contains=[value])

    def filter_queryset(self, queryset):
        if not (self.data.get("scan") or self.data.get("scan__in")) and not (
            self.data.get("inserted_at")
            or self.data.get("inserted_at__date")
            or self.data.get("inserted_at__gte")
            or self.data.get("inserted_at__lte")
        ):
            raise ValidationError(
                [
                    {
                        "detail": "At least one date filter is required: filter[inserted_at], filter[inserted_at.gte], "
                        "or filter[inserted_at.lte].",
                        "status": 400,
                        "source": {"pointer": "/data/attributes/inserted_at"},
                        "code": "required",
                    }
                ]
            )

        cleaned = self.form.cleaned_data
        exact_date = cleaned.get("inserted_at") or cleaned.get("inserted_at__date")
        gte_date = cleaned.get("inserted_at__gte") or exact_date
        lte_date = cleaned.get("inserted_at__lte") or exact_date

        if gte_date is None:
            gte_date = datetime.now(timezone.utc).date()
        if lte_date is None:
            lte_date = datetime.now(timezone.utc).date()

        if abs(lte_date - gte_date) > timedelta(
            days=settings.FINDINGS_MAX_DAYS_IN_RANGE
        ):
            raise ValidationError(
                [
                    {
                        "detail": f"The date range cannot exceed {settings.FINDINGS_MAX_DAYS_IN_RANGE} days.",
                        "status": 400,
                        "source": {"pointer": "/data/attributes/inserted_at"},
                        "code": "invalid",
                    }
                ]
            )

        return super().filter_queryset(queryset)

    #  Convert filter values to UUIDv7 values for use with partitioning
    def filter_scan_id(self, queryset, name, value):
        try:
            value_uuid = transform_into_uuid7(value)
            start = uuid7_start(value_uuid)
            end = uuid7_end(value_uuid, settings.FINDINGS_TABLE_PARTITION_MONTHS)
        except ValidationError as validation_error:
            detail = str(validation_error.detail[0])
            raise ValidationError(
                [
                    {
                        "detail": detail,
                        "status": 400,
                        "source": {"pointer": "/data/relationships/scan"},
                        "code": "invalid",
                    }
                ]
            )

        return (
            queryset.filter(id__gte=start).filter(id__lt=end).filter(scan_id=value_uuid)
        )

    def filter_scan_id_in(self, queryset, name, value):
        try:
            uuid_list = [
                transform_into_uuid7(value_uuid)
                for value_uuid in value
                if value_uuid is not None
            ]

            start, end = uuid7_range(uuid_list)
        except ValidationError as validation_error:
            detail = str(validation_error.detail[0])
            raise ValidationError(
                [
                    {
                        "detail": detail,
                        "status": 400,
                        "source": {"pointer": "/data/relationships/scan"},
                        "code": "invalid",
                    }
                ]
            )
        if start == end:
            return queryset.filter(id__gte=start).filter(scan_id__in=uuid_list)
        else:
            return (
                queryset.filter(id__gte=start)
                .filter(id__lt=end)
                .filter(scan_id__in=uuid_list)
            )

    def filter_inserted_at(self, queryset, name, value):
        datetime_value = self.maybe_date_to_datetime(value)
        start = uuid7_start(datetime_to_uuid7(datetime_value))
        end = uuid7_start(datetime_to_uuid7(datetime_value + timedelta(days=1)))

        return queryset.filter(id__gte=start, id__lt=end)

    def filter_inserted_at_gte(self, queryset, name, value):
        datetime_value = self.maybe_date_to_datetime(value)
        start = uuid7_start(datetime_to_uuid7(datetime_value))

        return queryset.filter(id__gte=start)

    def filter_inserted_at_lte(self, queryset, name, value):
        datetime_value = self.maybe_date_to_datetime(value)
        end = uuid7_start(datetime_to_uuid7(datetime_value + timedelta(days=1)))

        return queryset.filter(id__lt=end)

    @staticmethod
    def maybe_date_to_datetime(value):
        dt = value
        if isinstance(value, date):
            dt = datetime.combine(value, datetime.min.time(), tzinfo=timezone.utc)
        return dt


class LatestFindingFilter(CommonFindingFilters):
    class Meta:
        model = Finding
        fields = {
            "id": ["exact", "in"],
            "uid": ["exact", "in"],
            "delta": ["exact", "in"],
            "status": ["exact", "in"],
            "severity": ["exact", "in"],
            "impact": ["exact", "in"],
            "check_id": ["exact", "in", "icontains"],
        }
        filter_overrides = {
            FindingDeltaEnumField: {
                "filter_class": CharFilter,
            },
            StatusEnumField: {
                "filter_class": CharFilter,
            },
            SeverityEnumField: {
                "filter_class": CharFilter,
            },
        }


class FindingGroupFilter(CommonFindingFilters):
    """
    Filter for FindingGroup aggregations.

    Requires at least one date filter for performance (partition pruning).
    Inherits all provider, status, severity, region, service filters from CommonFindingFilters.
    """

    inserted_at = DateFilter(method="filter_inserted_at", lookup_expr="date")
    inserted_at__date = DateFilter(method="filter_inserted_at", lookup_expr="date")
    inserted_at__gte = DateFilter(
        method="filter_inserted_at_gte",
        help_text=f"Maximum date range is {settings.FINDINGS_MAX_DAYS_IN_RANGE} days.",
    )
    inserted_at__lte = DateFilter(
        method="filter_inserted_at_lte",
        help_text=f"Maximum date range is {settings.FINDINGS_MAX_DAYS_IN_RANGE} days.",
    )

    check_id = CharFilter(field_name="check_id", lookup_expr="exact")
    check_id__in = CharInFilter(field_name="check_id", lookup_expr="in")
    check_id__icontains = CharFilter(field_name="check_id", lookup_expr="icontains")

    class Meta:
        model = Finding
        fields = {
            "check_id": ["exact", "in", "icontains"],
        }

    def filter_queryset(self, queryset):
        """Validate that at least one date filter is provided."""
        if not (
            self.data.get("inserted_at")
            or self.data.get("inserted_at__date")
            or self.data.get("inserted_at__gte")
            or self.data.get("inserted_at__lte")
        ):
            raise ValidationError(
                [
                    {
                        "detail": "At least one date filter is required: filter[inserted_at], filter[inserted_at.gte], "
                        "or filter[inserted_at.lte].",
                        "status": 400,
                        "source": {"pointer": "/data/attributes/inserted_at"},
                        "code": "required",
                    }
                ]
            )

        # Validate date range doesn't exceed maximum
        cleaned = self.form.cleaned_data
        exact_date = cleaned.get("inserted_at") or cleaned.get("inserted_at__date")
        gte_date = cleaned.get("inserted_at__gte") or exact_date
        lte_date = cleaned.get("inserted_at__lte") or exact_date

        if gte_date is None:
            gte_date = datetime.now(timezone.utc).date()
        if lte_date is None:
            lte_date = datetime.now(timezone.utc).date()

        if abs(lte_date - gte_date) > timedelta(
            days=settings.FINDINGS_MAX_DAYS_IN_RANGE
        ):
            raise ValidationError(
                [
                    {
                        "detail": f"The date range cannot exceed {settings.FINDINGS_MAX_DAYS_IN_RANGE} days.",
                        "status": 400,
                        "source": {"pointer": "/data/attributes/inserted_at"},
                        "code": "invalid",
                    }
                ]
            )

        return super().filter_queryset(queryset)

    def filter_inserted_at(self, queryset, name, value):
        """Filter by exact date using UUIDv7 partition-aware filtering."""
        datetime_value = self._maybe_date_to_datetime(value)
        start = uuid7_start(datetime_to_uuid7(datetime_value))
        end = uuid7_start(datetime_to_uuid7(datetime_value + timedelta(days=1)))
        return queryset.filter(id__gte=start, id__lt=end)

    def filter_inserted_at_gte(self, queryset, name, value):
        """Filter by start date using UUIDv7 partition-aware filtering."""
        datetime_value = self._maybe_date_to_datetime(value)
        start = uuid7_start(datetime_to_uuid7(datetime_value))
        return queryset.filter(id__gte=start)

    def filter_inserted_at_lte(self, queryset, name, value):
        """Filter by end date using UUIDv7 partition-aware filtering."""
        datetime_value = self._maybe_date_to_datetime(value)
        end = uuid7_start(datetime_to_uuid7(datetime_value + timedelta(days=1)))
        return queryset.filter(id__lt=end)

    @staticmethod
    def _maybe_date_to_datetime(value):
        """Convert date to datetime if needed."""
        dt = value
        if isinstance(value, date):
            dt = datetime.combine(value, datetime.min.time(), tzinfo=timezone.utc)
        return dt


class LatestFindingGroupFilter(CommonFindingFilters):
    """
    Filter for FindingGroup resources in /latest endpoint.

    Same as FindingGroupFilter but without date validation.
    """

    check_id = CharFilter(field_name="check_id", lookup_expr="exact")
    check_id__in = CharInFilter(field_name="check_id", lookup_expr="in")
    check_id__icontains = CharFilter(field_name="check_id", lookup_expr="icontains")

    class Meta:
        model = Finding
        fields = {
            "check_id": ["exact", "in", "icontains"],
        }


class FindingGroupSummaryFilter(FilterSet):
    """
    Filter for FindingGroupDailySummary queries.

    Filters the pre-aggregated summary table by date range, check_id, and provider.
    Requires at least one date filter for performance.
    """

    inserted_at = DateFilter(method="filter_inserted_at", lookup_expr="date")
    inserted_at__date = DateFilter(method="filter_inserted_at", lookup_expr="date")
    inserted_at__gte = DateFilter(
        method="filter_inserted_at_gte",
        help_text=f"Maximum date range is {settings.FINDINGS_MAX_DAYS_IN_RANGE} days.",
    )
    inserted_at__lte = DateFilter(
        method="filter_inserted_at_lte",
        help_text=f"Maximum date range is {settings.FINDINGS_MAX_DAYS_IN_RANGE} days.",
    )

    # Check ID filters
    check_id = CharFilter(field_name="check_id", lookup_expr="exact")
    check_id__in = CharInFilter(field_name="check_id", lookup_expr="in")
    check_id__icontains = CharFilter(field_name="check_id", lookup_expr="icontains")

    # Provider filters
    provider_id = UUIDFilter(field_name="provider_id", lookup_expr="exact")
    provider_id__in = UUIDInFilter(field_name="provider_id", lookup_expr="in")
    provider_type = ChoiceFilter(
        field_name="provider__provider", choices=Provider.ProviderChoices.choices
    )
    provider_type__in = CharInFilter(field_name="provider__provider", lookup_expr="in")

    class Meta:
        model = FindingGroupDailySummary
        fields = {
            "check_id": ["exact", "in", "icontains"],
            "inserted_at": ["date", "gte", "lte"],
            "provider_id": ["exact", "in"],
        }

    def filter_queryset(self, queryset):
        if not (
            self.data.get("inserted_at")
            or self.data.get("inserted_at__date")
            or self.data.get("inserted_at__gte")
            or self.data.get("inserted_at__lte")
        ):
            raise ValidationError(
                [
                    {
                        "detail": "At least one date filter is required: filter[inserted_at], filter[inserted_at.gte], "
                        "or filter[inserted_at.lte].",
                        "status": 400,
                        "source": {"pointer": "/data/attributes/inserted_at"},
                        "code": "required",
                    }
                ]
            )

        cleaned = self.form.cleaned_data
        exact_date = cleaned.get("inserted_at") or cleaned.get("inserted_at__date")
        gte_date = cleaned.get("inserted_at__gte") or exact_date
        lte_date = cleaned.get("inserted_at__lte") or exact_date

        if gte_date is None:
            gte_date = datetime.now(timezone.utc).date()
        if lte_date is None:
            lte_date = datetime.now(timezone.utc).date()

        if abs(lte_date - gte_date) > timedelta(
            days=settings.FINDINGS_MAX_DAYS_IN_RANGE
        ):
            raise ValidationError(
                [
                    {
                        "detail": f"The date range cannot exceed {settings.FINDINGS_MAX_DAYS_IN_RANGE} days.",
                        "status": 400,
                        "source": {"pointer": "/data/attributes/inserted_at"},
                        "code": "invalid",
                    }
                ]
            )

        return super().filter_queryset(queryset)

    def filter_inserted_at(self, queryset, name, value):
        """Filter by exact inserted_at date."""
        datetime_value = self._maybe_date_to_datetime(value)
        start = datetime_value
        end = datetime_value + timedelta(days=1)
        return queryset.filter(inserted_at__gte=start, inserted_at__lt=end)

    def filter_inserted_at_gte(self, queryset, name, value):
        """Filter by inserted_at >= value (date boundary)."""
        datetime_value = self._maybe_date_to_datetime(value)
        return queryset.filter(inserted_at__gte=datetime_value)

    def filter_inserted_at_lte(self, queryset, name, value):
        """Filter by inserted_at <= value (inclusive date boundary)."""
        datetime_value = self._maybe_date_to_datetime(value)
        return queryset.filter(inserted_at__lt=datetime_value + timedelta(days=1))

    @staticmethod
    def _maybe_date_to_datetime(value):
        dt = value
        if isinstance(value, date):
            dt = datetime.combine(value, datetime.min.time(), tzinfo=timezone.utc)
        return dt


class LatestFindingGroupSummaryFilter(FilterSet):
    """
    Filter for FindingGroupDailySummary /latest endpoint.

    Same as FindingGroupSummaryFilter but without date validation.
    Used when the endpoint automatically determines the date.
    """

    # Check ID filters
    check_id = CharFilter(field_name="check_id", lookup_expr="exact")
    check_id__in = CharInFilter(field_name="check_id", lookup_expr="in")
    check_id__icontains = CharFilter(field_name="check_id", lookup_expr="icontains")

    # Provider filters
    provider_id = UUIDFilter(field_name="provider_id", lookup_expr="exact")
    provider_id__in = UUIDInFilter(field_name="provider_id", lookup_expr="in")
    provider_type = ChoiceFilter(
        field_name="provider__provider", choices=Provider.ProviderChoices.choices
    )
    provider_type__in = CharInFilter(field_name="provider__provider", lookup_expr="in")

    class Meta:
        model = FindingGroupDailySummary
        fields = {
            "check_id": ["exact", "in", "icontains"],
            "provider_id": ["exact", "in"],
        }


class ProviderSecretFilter(FilterSet):
    inserted_at = DateFilter(
        field_name="inserted_at",
        lookup_expr="date",
        help_text="Filter by date when the secret was added (format: YYYY-MM-DD)",
    )
    updated_at = DateFilter(
        field_name="updated_at",
        lookup_expr="date",
        help_text="Filter by date when the secret was updated (format: YYYY-MM-DD)",
    )
    provider = UUIDFilter(field_name="provider__id", lookup_expr="exact")

    class Meta:
        model = ProviderSecret
        fields = {
            "name": ["exact", "icontains"],
        }


class InvitationFilter(FilterSet):
    inserted_at = DateFilter(field_name="inserted_at", lookup_expr="date")
    updated_at = DateFilter(field_name="updated_at", lookup_expr="date")
    expires_at = DateFilter(field_name="expires_at", lookup_expr="date")
    state = ChoiceFilter(choices=Invitation.State.choices)
    state__in = ChoiceInFilter(choices=Invitation.State.choices, lookup_expr="in")

    class Meta:
        model = Invitation
        fields = {
            "email": ["exact", "icontains"],
            "inserted_at": ["date", "gte", "lte"],
            "updated_at": ["date", "gte", "lte"],
            "expires_at": ["date", "gte", "lte"],
            "inviter": ["exact"],
        }
        filter_overrides = {
            InvitationStateEnumField: {
                "filter_class": CharFilter,
            }
        }


class UserFilter(FilterSet):
    date_joined = DateFilter(field_name="date_joined", lookup_expr="date")

    class Meta:
        model = User
        fields = {
            "name": ["exact", "icontains"],
            "email": ["exact", "icontains"],
            "company_name": ["exact", "icontains"],
            "date_joined": ["date", "gte", "lte"],
            "is_active": ["exact"],
        }


class RoleFilter(FilterSet):
    inserted_at = DateFilter(field_name="inserted_at", lookup_expr="date")
    updated_at = DateFilter(field_name="updated_at", lookup_expr="date")
    permission_state = ChoiceFilter(
        choices=PermissionChoices.choices, method="filter_permission_state"
    )

    def filter_permission_state(self, queryset, name, value):
        return Role.filter_by_permission_state(queryset, value)

    class Meta:
        model = Role
        fields = {
            "id": ["exact", "in"],
            "name": ["exact", "in"],
            "inserted_at": ["gte", "lte"],
            "updated_at": ["gte", "lte"],
        }


class ComplianceOverviewFilter(FilterSet):
    inserted_at = DateFilter(field_name="inserted_at", lookup_expr="date")
    scan_id = UUIDFilter(field_name="scan_id", required=True)
    region = CharFilter(field_name="region")

    class Meta:
        model = ComplianceRequirementOverview
        fields = {
            "inserted_at": ["date", "gte", "lte"],
            "compliance_id": ["exact", "icontains"],
            "framework": ["exact", "iexact", "icontains"],
            "version": ["exact", "icontains"],
            "region": ["exact", "icontains", "in"],
        }


class ScanSummaryFilter(FilterSet):
    inserted_at = DateFilter(field_name="inserted_at", lookup_expr="date")
    provider_id = UUIDFilter(field_name="scan__provider__id", lookup_expr="exact")
    provider_id__in = UUIDInFilter(field_name="scan__provider__id", lookup_expr="in")
    provider_type = ChoiceFilter(
        field_name="scan__provider__provider", choices=Provider.ProviderChoices.choices
    )
    provider_type__in = ChoiceInFilter(
        field_name="scan__provider__provider", choices=Provider.ProviderChoices.choices
    )
    region = CharFilter(field_name="region")

    class Meta:
        model = ScanSummary
        fields = {
            "inserted_at": ["date", "gte", "lte"],
            "region": ["exact", "icontains", "in"],
        }


class DailySeveritySummaryFilter(FilterSet):
    """Filter for findings_severity/timeseries endpoint."""

    MAX_DATE_RANGE_DAYS = 365

    provider_id = UUIDFilter(field_name="provider_id", lookup_expr="exact")
    provider_id__in = UUIDInFilter(field_name="provider_id", lookup_expr="in")
    provider_type = ChoiceFilter(
        field_name="provider__provider", choices=Provider.ProviderChoices.choices
    )
    provider_type__in = ChoiceInFilter(
        field_name="provider__provider", choices=Provider.ProviderChoices.choices
    )
    date_from = DateFilter(method="filter_noop")
    date_to = DateFilter(method="filter_noop")

    class Meta:
        model = DailySeveritySummary
        fields = ["provider_id"]

    def filter_noop(self, queryset, name, value):
        return queryset

    def filter_queryset(self, queryset):
        if not self.data.get("date_from"):
            raise ValidationError(
                [
                    {
                        "detail": "This query parameter is required.",
                        "status": "400",
                        "source": {"pointer": "filter[date_from]"},
                        "code": "required",
                    }
                ]
            )

        today = date.today()
        date_from = self.form.cleaned_data.get("date_from")
        date_to = min(self.form.cleaned_data.get("date_to") or today, today)

        if (date_to - date_from).days > self.MAX_DATE_RANGE_DAYS:
            raise ValidationError(
                [
                    {
                        "detail": f"Date range cannot exceed {self.MAX_DATE_RANGE_DAYS} days.",
                        "status": "400",
                        "source": {"pointer": "filter[date_from]"},
                        "code": "invalid",
                    }
                ]
            )

        # View access
        self.request._date_from = date_from
        self.request._date_to = date_to

        # Apply date filter (only lte for fill-forward logic)
        queryset = queryset.filter(date__lte=date_to)

        return super().filter_queryset(queryset)


class ScanSummarySeverityFilter(ScanSummaryFilter):
    """Filter for findings_severity ScanSummary endpoint - includes status filters"""

    # Custom status filters - only for severity grouping endpoint
    status = ChoiceFilter(method="filter_status", choices=OverviewStatusChoices.choices)
    status__in = CharInFilter(method="filter_status_in", lookup_expr="in")

    def filter_status(self, queryset, name, value):
        # Validate the status value
        if value not in [choice[0] for choice in OverviewStatusChoices.choices]:
            raise ValidationError(f"Invalid status value: {value}")

        # Apply the filter by annotating the queryset with the status field
        if value == OverviewStatusChoices.FAIL:
            return queryset.annotate(status_count=F("fail"))
        elif value == OverviewStatusChoices.PASS:
            return queryset.annotate(status_count=F("_pass"))
        else:
            # Exclude muted findings by default
            return queryset.annotate(status_count=F("_pass") + F("fail"))

    def filter_status_in(self, queryset, name, value):
        # Validate the status values
        valid_statuses = [choice[0] for choice in OverviewStatusChoices.choices]
        for status_val in value:
            if status_val not in valid_statuses:
                raise ValidationError(f"Invalid status value: {status_val}")

        # If all statuses or no valid statuses, exclude muted findings (pass + fail)
        if (
            set(value)
            >= {
                OverviewStatusChoices.FAIL,
                OverviewStatusChoices.PASS,
            }
            or not value
        ):
            return queryset.annotate(status_count=F("_pass") + F("fail"))

        # Build the sum expression based on status values
        sum_expression = None
        for status in value:
            if status == OverviewStatusChoices.FAIL:
                field_expr = F("fail")
            elif status == OverviewStatusChoices.PASS:
                field_expr = F("_pass")
            else:
                continue

            if sum_expression is None:
                sum_expression = field_expr
            else:
                sum_expression = sum_expression + field_expr

        if sum_expression is None:
            return queryset.annotate(status_count=F("_pass") + F("fail"))

        return queryset.annotate(status_count=sum_expression)

    class Meta:
        model = ScanSummary
        fields = {
            "inserted_at": ["date", "gte", "lte"],
            "region": ["exact", "icontains", "in"],
        }


class IntegrationFilter(FilterSet):
    inserted_at = DateFilter(field_name="inserted_at", lookup_expr="date")
    integration_type = ChoiceFilter(choices=Integration.IntegrationChoices.choices)
    integration_type__in = ChoiceInFilter(
        choices=Integration.IntegrationChoices.choices,
        field_name="integration_type",
        lookup_expr="in",
    )

    class Meta:
        model = Integration
        fields = {
            "inserted_at": ["date", "gte", "lte"],
        }


class ProcessorFilter(FilterSet):
    processor_type = ChoiceFilter(choices=Processor.ProcessorChoices.choices)
    processor_type__in = ChoiceInFilter(
        choices=Processor.ProcessorChoices.choices,
        field_name="processor_type",
        lookup_expr="in",
    )


class IntegrationJiraFindingsFilter(FilterSet):
    # To be expanded as needed
    finding_id = UUIDFilter(field_name="id", lookup_expr="exact")
    finding_id__in = UUIDInFilter(field_name="id", lookup_expr="in")

    class Meta:
        model = Finding
        fields = {}

    def filter_queryset(self, queryset):
        # Validate that there is at least one filter provided
        if not self.data:
            raise ValidationError(
                {
                    "findings": "No finding filters provided. At least one filter is required."
                }
            )
        return super().filter_queryset(queryset)


class TenantApiKeyFilter(FilterSet):
    inserted_at = DateFilter(field_name="created", lookup_expr="date")
    inserted_at__gte = DateFilter(field_name="created", lookup_expr="gte")
    inserted_at__lte = DateFilter(field_name="created", lookup_expr="lte")
    expires_at = DateFilter(field_name="expiry_date", lookup_expr="date")
    expires_at__gte = DateFilter(field_name="expiry_date", lookup_expr="gte")
    expires_at__lte = DateFilter(field_name="expiry_date", lookup_expr="lte")

    class Meta:
        model = TenantAPIKey
        fields = {
            "prefix": ["exact", "icontains"],
            "revoked": ["exact"],
            "name": ["exact", "icontains"],
        }


class LighthouseProviderConfigFilter(FilterSet):
    provider_type = ChoiceFilter(
        choices=LighthouseProviderConfiguration.LLMProviderChoices.choices
    )
    provider_type__in = ChoiceInFilter(
        choices=LighthouseProviderConfiguration.LLMProviderChoices.choices,
        field_name="provider_type",
        lookup_expr="in",
    )
    is_active = BooleanFilter()

    class Meta:
        model = LighthouseProviderConfiguration
        fields = {
            "provider_type": ["exact", "in"],
            "is_active": ["exact"],
        }


class LighthouseProviderModelsFilter(FilterSet):
    provider_type = ChoiceFilter(
        choices=LighthouseProviderConfiguration.LLMProviderChoices.choices,
        field_name="provider_configuration__provider_type",
    )
    provider_type__in = ChoiceInFilter(
        choices=LighthouseProviderConfiguration.LLMProviderChoices.choices,
        field_name="provider_configuration__provider_type",
        lookup_expr="in",
    )

    # Allow filtering by model id
    model_id = CharFilter(field_name="model_id", lookup_expr="exact")
    model_id__icontains = CharFilter(field_name="model_id", lookup_expr="icontains")
    model_id__in = CharInFilter(field_name="model_id", lookup_expr="in")

    class Meta:
        model = LighthouseProviderModels
        fields = {
            "model_id": ["exact", "icontains", "in"],
        }


class MuteRuleFilter(FilterSet):
    inserted_at = DateFilter(field_name="inserted_at", lookup_expr="date")
    updated_at = DateFilter(field_name="updated_at", lookup_expr="date")
    created_by = UUIDFilter(field_name="created_by__id", lookup_expr="exact")

    class Meta:
        model = MuteRule
        fields = {
            "id": ["exact", "in"],
            "name": ["exact", "icontains"],
            "reason": ["icontains"],
            "enabled": ["exact"],
            "inserted_at": ["gte", "lte"],
            "updated_at": ["gte", "lte"],
        }


class ThreatScoreSnapshotFilter(FilterSet):
    """
    Filter for ThreatScore snapshots.
    Allows filtering by scan, provider, compliance_id, and date ranges.
    """

    inserted_at = DateFilter(field_name="inserted_at", lookup_expr="date")
    scan_id = UUIDFilter(field_name="scan__id", lookup_expr="exact")
    scan_id__in = UUIDInFilter(field_name="scan__id", lookup_expr="in")
    provider_id = UUIDFilter(field_name="provider__id", lookup_expr="exact")
    provider_id__in = UUIDInFilter(field_name="provider__id", lookup_expr="in")
    provider_type = ChoiceFilter(
        field_name="provider__provider", choices=Provider.ProviderChoices.choices
    )
    provider_type__in = ChoiceInFilter(
        field_name="provider__provider",
        choices=Provider.ProviderChoices.choices,
        lookup_expr="in",
    )
    compliance_id = CharFilter(field_name="compliance_id", lookup_expr="exact")
    compliance_id__in = CharInFilter(field_name="compliance_id", lookup_expr="in")

    class Meta:
        model = ThreatScoreSnapshot
        fields = {
            "scan": ["exact", "in"],
            "provider": ["exact", "in"],
            "compliance_id": ["exact", "in"],
            "inserted_at": ["date", "gte", "lte"],
            "overall_score": ["exact", "gte", "lte"],
        }


class AttackSurfaceOverviewFilter(BaseScanProviderFilter):
    """Filter for attack surface overview aggregations by provider."""

    class Meta(BaseScanProviderFilter.Meta):
        model = AttackSurfaceOverview


class CategoryOverviewFilter(BaseScanProviderFilter):
    """Filter for category overview aggregations by provider."""

    category = CharFilter(field_name="category", lookup_expr="exact")
    category__in = CharInFilter(field_name="category", lookup_expr="in")

    class Meta(BaseScanProviderFilter.Meta):
        model = ScanCategorySummary
        fields = {}


class ResourceGroupOverviewFilter(FilterSet):
    provider_id = UUIDFilter(field_name="scan__provider__id", lookup_expr="exact")
    provider_id__in = UUIDInFilter(field_name="scan__provider__id", lookup_expr="in")
    provider_type = ChoiceFilter(
        field_name="scan__provider__provider", choices=Provider.ProviderChoices.choices
    )
    provider_type__in = ChoiceInFilter(
        field_name="scan__provider__provider",
        choices=Provider.ProviderChoices.choices,
        lookup_expr="in",
    )
    resource_group = CharFilter(field_name="resource_group", lookup_expr="exact")
    resource_group__in = CharInFilter(field_name="resource_group", lookup_expr="in")

    class Meta:
        model = ScanGroupSummary
        fields = {}


class ComplianceWatchlistFilter(BaseProviderFilter):
    """Filter for compliance watchlist overview by provider."""

    class Meta(BaseProviderFilter.Meta):
        model = ProviderComplianceScore
