from django.urls import include, path

from api.health import LivenessView, ReadinessView

urlpatterns = [
    path("api/v1/", include("api.v1.urls")),
    path("health/live", LivenessView.as_view(), name="health-live"),
    path("health/ready", ReadinessView.as_view(), name="health-ready"),
]
