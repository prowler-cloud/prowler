from django.conf import settings
from django.urls import include, path

urlpatterns = [
    path("api/v1/", include("api.v1.urls")),
]

if getattr(settings, "DJANGO_SILK_ENABLED", False):
    urlpatterns.append(path("silk/", include("silk.urls", namespace="silk")))
