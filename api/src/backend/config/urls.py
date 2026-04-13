from django.conf import settings
from django.urls import include, path

urlpatterns = [
    path("api/v1/", include("api.v1.urls")),
]

if settings.CLOUDGOV_UAA_ENABLED:
    from api.cloudgov.views import CloudGovCompleteView

    urlpatterns.append(path("auth/", include("uaa_client.urls")))
    urlpatterns.append(
        path(
            "auth/complete/cloudgov/",
            CloudGovCompleteView.as_view(),
            name="cloudgov-complete",
        )
    )
