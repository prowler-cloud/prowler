from django_filters.rest_framework import FilterSet
from rest_framework_json_api.django_filters.backends import DjangoFilterBackend

from api.models import Tenant


class CustomDjangoFilterBackend(DjangoFilterBackend):
    def to_html(self, _request, _queryset, _view):
        """Override this method to use the Browsable API in dev environments.

        This disables the HTML render for the default filter.
        """
        return None


class BaseFilter(FilterSet):
    class Meta:
        model = None
        fields = {
            "inserted_at": ["exact", "gte", "lte"],
            "updated_at": ["exact", "gte", "lte"],
        }


class TenantFilter(BaseFilter):
    class Meta(BaseFilter.Meta):
        model = Tenant
        fields = {
            **BaseFilter.Meta.fields,
            "name": ["exact", "icontains"],
        }
