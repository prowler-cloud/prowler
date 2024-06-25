from django.urls import path

from .views import AuditListView, CloudAccountListView

urlpatterns = [
    path('providers/<str:provider_id>/accounts', CloudAccountListView.as_view(), name='cloud-account-list'),
    path('providers/aws/audits', AuditListView.as_view(), name='aws-audit-list'),
]
