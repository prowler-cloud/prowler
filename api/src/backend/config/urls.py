from django.conf import settings
from django.urls import include, path

urlpatterns = [
    path("api/v1/", include("api.v1.urls")),
]

if settings.CLOUDGOV_UAA_ENABLED:
    urlpatterns.append(path("auth/", include("uaa_client.urls")))
