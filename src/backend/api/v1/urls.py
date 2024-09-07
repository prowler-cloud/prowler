from django.urls import path, include
from drf_spectacular.views import SpectacularRedocView
from rest_framework import routers

from api.v1.views import (
    SchemaView,
    TenantViewSet,
    ProviderViewSet,
    ScanViewSet,
    TaskViewSet,
)

router = routers.DefaultRouter(trailing_slash=False)

router.register(r"tenants", TenantViewSet, basename="tenant")
router.register(r"providers", ProviderViewSet, basename="provider")
router.register(r"scans", ScanViewSet, basename="scan")
router.register(r"tasks", TaskViewSet, basename="task")

urlpatterns = [
    path("", include(router.urls)),
    path("schema", SchemaView.as_view(), name="schema"),
    path("docs", SpectacularRedocView.as_view(url_name="schema"), name="docs"),
]
