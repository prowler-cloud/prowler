from django.conf import settings as django_settings
from django.utils.decorators import method_decorator
from django.views.decorators.cache import cache_control
from drf_spectacular.settings import spectacular_settings
from drf_spectacular.utils import extend_schema, extend_schema_view
from drf_spectacular.views import SpectacularAPIView
from rest_framework import status, viewsets
from rest_framework.decorators import action
from rest_framework_json_api.views import Response
from api.filters import TenantFilter
from rest_framework.generics import ListCreateAPIView
from api.models import Test
from api.rls import Tenant
from api.serializers import TenantSerializer, TestSerializer
from api.views.base_views import BaseViewSet

CACHE_DECORATOR = cache_control(
    max_age=django_settings.CACHE_MAX_AGE,
    stale_while_revalidate=django_settings.CACHE_STALE_WHILE_REVALIDATE,
)


@extend_schema(exclude=True)
class SchemaView(SpectacularAPIView):
    serializer_class = None

    def get(self, request, *args, **kwargs):
        spectacular_settings.TITLE = "Prowler RESTful API"
        spectacular_settings.VERSION = "1.0.0"
        spectacular_settings.DESCRIPTION = (
            "Prowler RESTful API specification.\n\nThis file is auto-generated."
        )
        return super().get(request, *args, **kwargs)


@extend_schema_view(
    list=extend_schema(
        summary="List all tenants",
        description="Retrieve a list of all tenants with options for filtering by various criteria.",
    ),
    retrieve=extend_schema(
        summary="Retrieve data from a tenant",
        description="Fetch detailed information about a specific tenant by their ID.",
    ),
    create=extend_schema(
        summary="Create a new tenant",
        description="Add a new tenant to the system by providing the required tenant details.",
    ),
    partial_update=extend_schema(
        summary="Partially update a tenant",
        description="Update certain fields of an existing tenant's information without affecting other fields.",
    ),
    destroy=extend_schema(
        summary="Delete a tenant",
        description="Remove a tenant from the system by their ID.",
    ),
)
@method_decorator(CACHE_DECORATOR, name="list")
@method_decorator(CACHE_DECORATOR, name="retrieve")
class TenantViewSet(BaseViewSet):
    queryset = Tenant.objects.all()
    serializer_class = TenantSerializer
    http_method_names = ["get", "post", "patch", "delete"]
    filterset_class = TenantFilter
    search_fields = ["name"]
    ordering = ["inserted_at"]
    ordering_fields = ["name", "inserted_at", "updated_at"]

    def get_queryset(self):
        return Tenant.objects.all()


@extend_schema_view(
    list=extend_schema(
        summary="List all providers",
        description="Retrieve a list of all providers with options for filtering by various criteria.",
    ),
    retrieve=extend_schema(
        summary="Retrieve data from a provider",
        description="Fetch detailed information about a specific provider by their ID.",
    ),
    create=extend_schema(
        summary="Create a new provider",
        description="Add a new provider to the system by providing the required provider details.",
    ),
    partial_update=extend_schema(
        summary="Partially update a provider",
        description="Update certain fields of an existing provider's information without affecting other fields.",
    ),
    destroy=extend_schema(
        summary="Delete a provider",
        description="Remove a provider from the system by their ID.",
    ),
)
@method_decorator(CACHE_DECORATOR, name="list")
@method_decorator(CACHE_DECORATOR, name="retrieve")
class ProviderViewSet(viewsets.ViewSet):
    content_location_header = {
        "Content-Location": "https://api.prowler.com/api/v1/tasks/5234"
    }

    mock_links_data = {
        "first": "https://api.prowler.com/api/v1/providers?page%5Bnumber%5D=1",
        "last": "https://api.prowler.com/api/v1/providers?page%5Bnumber%5D=1",
        "next": None,
        "prev": None,
    }

    mock_provider_data = [
        {
            "id": "5fd8f121-269e-4715-84cf-f92373f15dfa",
            "type": "providers",
            "attributes": {
                "provider": "aws",
                "provider_id": "1234567890",
                "alias": "mock_aws_connected",
                "connection": {
                    "connected": True,
                    "last_checked_at": "2024-07-17T09:55:14.191475Z",
                },
                "scanner_args": {
                    "only_logs": True,
                    "excluded_checks": [
                        "awslambda_function_no_secrets_in_code",
                        "cloudwatch_log_group_no_secrets_in_logs",
                    ],
                    "aws_retries_max_attempts": 5,
                },
                "last_resource_count": 1234,
                "inserted_at": "2024-07-17T09:55:14.191475Z",
                "updated_at": "2024-07-17T09:55:14.191475Z",
                "created_by": {
                    "object": "user",
                    "id": "eea048ab-7cb3-47eb-9e5e-dce591ade41f",
                },
            },
        },
        {
            "id": "16aaeb4e-d3cd-4bb6-86f8-6c39cf93821e",
            "type": "providers",
            "attributes": {
                "provider": "aws",
                "provider_id": "1234567891",
                "alias": "mock_aws_not_connected",
                "connection": {
                    "connected": False,
                    "last_checked_at": "2024-07-17T09:55:18.987425Z",
                },
                "scanner_args": {
                    "only_logs": True,
                    "excluded_checks": [
                        "awslambda_function_no_secrets_in_code",
                        "cloudwatch_log_group_no_secrets_in_logs",
                    ],
                    "aws_retries_max_attempts": 5,
                },
                "last_resource_count": 0,
                "inserted_at": "2024-07-17T09:55:18.987425Z",
                "updated_at": "2024-07-17T09:55:18.987425Z",
                "created_by": {
                    "object": "user",
                    "id": "a8f5e964-5964-4aaf-9176-844e2c3b0716",
                },
            },
        },
        {
            "id": "63f16b03-7849-4054-b40b-300e331f46f0",
            "type": "providers",
            "attributes": {
                "provider": "gcp",
                "provider_id": "1234567895",
                "alias": "mock_gcp",
                "connection": {
                    "connected": True,
                    "last_checked_at": "2024-07-17T09:55:18.987425Z",
                },
                "scanner_args": {
                    "only_logs": True,
                    "excluded_checks": [
                        "apikeys_key_exists",
                        "cloudsql_instance_public_ip",
                    ],
                    "excluded_services": ["kms"],
                },
                "last_resource_count": 1111,
                "inserted_at": "2024-07-17T09:55:18.987425Z",
                "updated_at": "2024-07-17T09:55:18.987425Z",
                "created_by": {
                    "object": "user",
                    "id": "eea048ab-7cb3-47eb-9e5e-dce591ade41f",
                },
            },
        },
    ]

    mock_meta_data = {"version": "v1"}
    http_method_names = ["get", "post", "patch", "delete"]
    resource_name = False

    def list(self, request, *args, **kwargs):
        mock_data = {
            "links": self.mock_links_data,
            "data": self.mock_provider_data,
            "meta": {
                "pagination": {
                    "page": 1,
                    "pages": 1,
                    "count": len(self.mock_provider_data),
                },
                **self.mock_meta_data,
            },
        }

        return Response(mock_data, status=status.HTTP_200_OK)

    def retrieve(self, request, pk=None, *args, **kwargs):
        provider = next(
            (item for item in self.mock_provider_data if item["id"] == pk), None
        )
        if provider is not None:
            return Response({**provider, **self.mock_meta_data})
        return Response(
            [{"detail": "Not found.", "status": "404", "code": "not_found"}],
            status=status.HTTP_404_NOT_FOUND,
        )

    def create(self, request, *args, **kwargs):
        return Response(
            {"data": self.mock_provider_data[0], "meta": self.mock_meta_data},
            status.HTTP_201_CREATED,
        )

    def partial_update(self, request, *args, **kwargs):
        return Response(
            {"data": self.mock_provider_data[0], "meta": self.mock_meta_data},
            status.HTTP_200_OK,
        )

    def destroy(self, request, *args, **kwargs):
        task_mock = {
            "data": {
                "type": "tasks",
                "id": "5234",
                "attributes": {
                    "status": "pending",
                },
                "links": {"self": "/tasks/5234"},
            }
        }
        return Response(
            task_mock,
            status=status.HTTP_202_ACCEPTED,
            headers=self.content_location_header,
        )

    @extend_schema(
        summary="Check connection",
        description="Try to verify connection. For instance, Role & Credentials are set correctly",
    )
    @action(detail=False, methods=["post"], url_path="check_connection")
    def check_connection(self, request):
        connection_data_mock = {
            "meta": {"version": "v1"},
            "data": {
                "id": "63f16b03-7849-4054-b40b-300e331f46f0",
                "type": "providers",
                "attributes": {
                    "provider": "gcp",
                    "provider_id": "1234567895",
                    "alias": "mock_gcp",
                    "connection": {
                        "connected": True,
                        "last_checked_at": "2024-07-17T09:55:18.987425Z",
                    },
                    "scanner_args": {
                        "only_logs": True,
                        "excluded_checks": [
                            "apikeys_key_exists",
                            "cloudsql_instance_public_ip",
                        ],
                        "excluded_services": ["kms"],
                    },
                    "last_resource_count": 1111,
                    "inserted_at": "2024-07-17T09:55:18.987425Z",
                    "updated_at": "2024-07-17T09:55:18.987425Z",
                    "created_by": {
                        "object": "user",
                        "id": "eea048ab-7cb3-47eb-9e5e-dce591ade41f",
                    },
                },
            },
            "relationships": {
                "tenant": {
                    "links": {
                        "self": "http://api.prowler.com/api/v1/providers/41f1d90e-5e3b-4eb0-b565-893f277d96c1",
                        "related": "http://api.prowler.com/api/v1/tenants/22f9341e-4e13-44a8-996a-11f370696c54",
                    },
                    "data": {"type": "tenants", "id": "uuid"},
                },
                "credential": {
                    "links": {
                        "self": "http://api.prowler.com/api/v1/providers/41f1d90e-5e3b-4eb0-b565-893f277d96c1",
                        "related": "http://api.prowler.com/api/v1/credentials/22f9341e-4e13-44a8-996a-11f370696c54",
                    },
                    "data": {"type": "credentials", "id": "uuid"},
                },
                "schedules": {
                    "links": {
                        "self": "http://api.prowler.com/api/v1/providers/41f1d90e-5e3b-4eb0-b565-893f277d96c1",
                        "related": "http://api.prowler.com/api/v1/schedules/22f9341e-4e13-44a8-996a-11f370696c54",
                    },
                    "data": {
                        "type": "schedules",
                        "id": "ee15292e-687f-41cf-8652-30a8b7cded35",
                    },
                },
            },
        }

        return Response(connection_data_mock, status=status.HTTP_200_OK)


class TestView(ListCreateAPIView):
    serializer_class = TestSerializer
    queryset = Test.objects.all()
