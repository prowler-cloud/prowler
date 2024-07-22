from rest_framework.filters import SearchFilter
from rest_framework_json_api import filters
from rest_framework_json_api.views import ModelViewSet

from api.filters import CustomDjangoFilterBackend


class BaseViewSet(ModelViewSet):
    filter_backends = [
        filters.QueryParameterValidationFilter,
        filters.OrderingFilter,
        CustomDjangoFilterBackend,
        SearchFilter,
    ]

    filterset_fields = []
    search_fields = []

    ordering_fields = "__all__"
    ordering = ["id"]

    def get_queryset(self):
        raise NotImplementedError
