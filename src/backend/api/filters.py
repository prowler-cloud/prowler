from django_filters.rest_framework import FilterSet, BooleanFilter, CharFilter
from rest_framework_json_api.django_filters.backends import DjangoFilterBackend
from rest_framework_json_api.serializers import ValidationError

from api.db_utils import ProviderEnumField
from api.models import Provider, Scan
from api.rls import Tenant


def provider_enum_filter(queryset, value, lookup_field: str = "provider"):
    """
    Filter a queryset based on a provider value, using a specified lookup field.

    This function filters a given queryset by checking if the provided `value`
    matches a valid choice in the `Provider.ProviderChoices` enum. If the `value`
    is valid, the queryset is filtered using the specified `lookup_field`.
    Otherwise, a `ValidationError` is raised.

    Args:
        queryset (QuerySet): The Django queryset to be filtered.
        value (str): The value to filter the queryset by, which must be a valid
                     option in `Provider.ProviderChoices`.
        lookup_field (str): The field or lookup path within the model used for
                            filtering the queryset. Defaults to "provider".

    Returns:
        QuerySet: A filtered queryset based on the provided `value` and `lookup_field`.

    Raises:
        ValidationError: If the provided `value` is not a valid choice in
                         `Provider.ProviderChoices`.
    """
    if value not in Provider.ProviderChoices:
        raise ValidationError(
            f"Invalid provider value: '{value}'. Valid values are: "
            f"{', '.join(Provider.ProviderChoices)}"
        )

    return queryset.filter(**{lookup_field: value})


class CustomDjangoFilterBackend(DjangoFilterBackend):
    def to_html(self, _request, _queryset, _view):
        """Override this method to use the Browsable API in dev environments.

        This disables the HTML render for the default filter.
        """
        return None


class TenantFilter(FilterSet):
    class Meta:
        model = Tenant
        fields = {
            "name": ["exact", "icontains"],
            "inserted_at": ["exact", "gte", "lte"],
            "updated_at": ["exact", "gte", "lte"],
        }


class ProviderFilter(FilterSet):
    connected = BooleanFilter()
    provider = CharFilter(method="filter_provider")

    def filter_provider(self, queryset, name, value):
        return provider_enum_filter(queryset, value)

    class Meta:
        model = Provider
        fields = {
            "provider": ["exact"],
            "provider_id": ["exact", "icontains"],
            "alias": ["exact", "icontains"],
            "inserted_at": ["exact", "gte", "lte"],
            "updated_at": ["exact", "gte", "lte"],
        }
        filter_overrides = {
            ProviderEnumField: {
                "filter_class": CharFilter,
            },
        }


class ScanFilter(FilterSet):
    provider = CharFilter(method="filter_provider")
    trigger = CharFilter(method="filter_trigger")

    def filter_provider(self, queryset, name, value):
        return provider_enum_filter(queryset, value, lookup_field="provider__provider")

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
            "provider_id": ["exact"],
            "name": ["exact", "icontains"],
            "started_at": ["exact", "gte", "lte"],
            "trigger": ["exact"],
        }
