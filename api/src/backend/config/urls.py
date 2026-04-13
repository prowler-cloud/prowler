from api.health import LivenessView, ReadinessView
from django.conf import settings
from django.urls import include, path

urlpatterns = [
    path("api/v1/", include("api.v1.urls")),
    path("health/live", LivenessView.as_view(), name="health-live"),
    path("health/ready", ReadinessView.as_view(), name="health-ready"),
]

if settings.CLOUDGOV_UAA_ENABLED:
    urlpatterns.append(path("auth/", include("uaa_client.urls")))
