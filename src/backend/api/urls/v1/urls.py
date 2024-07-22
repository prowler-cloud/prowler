from django.urls import path, include
from drf_spectacular.views import SpectacularRedocView
from rest_framework import routers

from api.views.v1.views import SchemaView, TenantViewSet

router = routers.DefaultRouter(trailing_slash=False)

router.register(r"tenants", TenantViewSet)


urlpatterns = [
    path("", include(router.urls)),
    path("schema", SchemaView.as_view(), name="schema"),
    path("docs", SpectacularRedocView.as_view(url_name="schema"), name="docs"),
]
