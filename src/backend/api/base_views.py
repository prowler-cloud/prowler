from rest_framework.exceptions import NotAuthenticated
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


class BaseRLSViewSet(BaseViewSet):
    def initial(self, request, *args, **kwargs):
        super().initial(request, *args, **kwargs)
        if "X-Tenant-ID" not in request.headers:
            # This will return a 403 until we implement authentication/authorization
            # https://www.django-rest-framework.org/api-guide/authentication/#unauthorized-and-forbidden-responses
            raise NotAuthenticated("X-Tenant-ID header is required")

    def get_serializer_context(self):
        context = super().get_serializer_context()
        tenant_id = self.request.headers.get("X-Tenant-ID")
        context["tenant_id"] = tenant_id
        return context
