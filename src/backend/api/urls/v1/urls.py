from django.urls import path
from drf_spectacular.views import SpectacularAPIView, SpectacularRedocView

from api.views.v1 import views

urlpatterns = [
    path("schema", SpectacularAPIView.as_view(), name="schema"),
    path("docs", SpectacularRedocView.as_view(url_name="schema"), name="docs"),
    # To delete. Use this url for development/testing purposes
    path("test", views.TestModelCreateView.as_view(), name="test-list"),
    path(
        "test/<int:pk>/",
        views.TestModelRetrieveUpdateDestroyView.as_view(),
        name="test-detail",
    ),
]
