from django_filters.rest_framework import FilterSet, BooleanFilter
from rest_framework_json_api.django_filters.backends import DjangoFilterBackend

from api.models import Provider
from api.rls import Tenant


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

    class Meta:
        model = Provider
        fields = {
            "provider": ["exact"],
            "provider_id": ["exact", "icontains"],
            "alias": ["exact", "icontains"],
            "inserted_at": ["exact", "gte", "lte"],
            "updated_at": ["exact", "gte", "lte"],
        }
