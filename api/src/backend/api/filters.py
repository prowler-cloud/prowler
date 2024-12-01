from datetime import date, datetime, timezone

from django.conf import settings
from django.db.models import Q
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
    ComplianceOverview,
    Finding,
    Invitation,
    Membership,
    Provider,
    ProviderGroup,
    ProviderSecret,
    Resource,
    ResourceTag,
    Scan,
    ScanSummary,
    SeverityChoices,
    StateChoices,
    StatusChoices,
    Task,
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
    inserted_at = DateFilter(field_name="inserted_at", lookup_expr="date")
    updated_at = DateFilter(field_name="updated_at", lookup_expr="date")
    connected = BooleanFilter()
    provider = ChoiceFilter(choices=Provider.ProviderChoices.choices)

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
        # We won't know what the user wants to filter on just based on the value,
        # and we don't want to build special filtering logic for every possible
        # provider tag spec, so we'll just do a full text search
        return queryset.filter(tags__text_search=value)


class FindingFilter(FilterSet):
    # We filter providers from the scan in findings
    provider = UUIDFilter(field_name="scan__provider__id", lookup_expr="exact")
    provider__in = UUIDInFilter(field_name="scan__provider__id", lookup_expr="in")
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

    resources = UUIDInFilter(field_name="resource__id", lookup_expr="in")

    region = CharFilter(field_name="resources__region")
    region__in = CharInFilter(field_name="resources__region", lookup_expr="in")
    region__icontains = CharFilter(
        field_name="resources__region", lookup_expr="icontains"
    )

    service = CharFilter(field_name="resources__service")
    service__in = CharInFilter(field_name="resources__service", lookup_expr="in")
    service__icontains = CharFilter(
        field_name="resources__service", lookup_expr="icontains"
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

    resource_type = CharFilter(field_name="resources__type")
    resource_type__in = CharInFilter(field_name="resources__type", lookup_expr="in")
    resource_type__icontains = CharFilter(
        field_name="resources__type", lookup_expr="icontains"
    )

    scan = UUIDFilter(method="filter_scan_id")
    scan__in = UUIDInFilter(method="filter_scan_id_in")

    inserted_at = DateFilter(method="filter_inserted_at", lookup_expr="date")
    inserted_at__date = DateFilter(method="filter_inserted_at", lookup_expr="date")
    inserted_at__gte = DateFilter(method="filter_inserted_at_gte")
    inserted_at__lte = DateFilter(method="filter_inserted_at_lte")

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
            queryset.filter(id__gte=start)
            .filter(id__lt=end)
            .filter(scan__id=value_uuid)
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
            return queryset.filter(id__gte=start).filter(scan__id__in=uuid_list)
        else:
            return (
                queryset.filter(id__gte=start)
                .filter(id__lt=end)
                .filter(scan__id__in=uuid_list)
            )

    def filter_inserted_at(self, queryset, name, value):
        value = self.maybe_date_to_datetime(value)
        start = uuid7_start(datetime_to_uuid7(value))

        return queryset.filter(id__gte=start).filter(inserted_at__date=value)

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


class ProviderSecretFilter(FilterSet):
    inserted_at = DateFilter(field_name="inserted_at", lookup_expr="date")
    updated_at = DateFilter(field_name="updated_at", lookup_expr="date")
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


class ComplianceOverviewFilter(FilterSet):
    inserted_at = DateFilter(field_name="inserted_at", lookup_expr="date")
    provider_type = ChoiceFilter(choices=Provider.ProviderChoices.choices)
    provider_type__in = ChoiceInFilter(choices=Provider.ProviderChoices.choices)
    scan_id = UUIDFilter(field_name="scan__id")

    class Meta:
        model = ComplianceOverview
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
    provider_type = ChoiceFilter(
        field_name="scan__provider__provider", choices=Provider.ProviderChoices.choices
    )
    provider_type__in = ChoiceInFilter(
        field_name="scan__provider__provider", choices=Provider.ProviderChoices.choices
    )
    region = CharFilter(field_name="region")
    muted_findings = BooleanFilter(method="filter_muted_findings")

    def filter_muted_findings(self, queryset, name, value):
        if not value:
            return queryset.exclude(muted__gt=0)
        return queryset

    class Meta:
        model = ScanSummary
        fields = {
            "inserted_at": ["date", "gte", "lte"],
            "region": ["exact", "icontains", "in"],
        }
