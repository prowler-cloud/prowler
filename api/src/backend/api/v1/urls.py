from django.urls import include, path
from drf_spectacular.views import SpectacularRedocView
from rest_framework_nested import routers

from api.v1.views import (
    ComplianceOverviewViewSet,
    CustomTokenObtainView,
    CustomTokenRefreshView,
    CustomTokenSwitchTenantView,
    FindingViewSet,
    GithubLoginCallback,
    GithubSocialLoginView,
    GoogleLoginCallback,
    GoogleSocialLoginView,
    InvitationAcceptViewSet,
    InvitationViewSet,
    LoginPage,
    MembershipViewSet,
    OverviewViewSet,
    ProviderGroupProvidersRelationshipView,
    ProviderGroupViewSet,
    ProviderSecretViewSet,
    ProviderViewSet,
    ResourceViewSet,
    RoleProviderGroupRelationshipView,
    RoleViewSet,
    ScanViewSet,
    ScheduleViewSet,
    SchemaView,
    TaskViewSet,
    TenantMembersViewSet,
    TenantViewSet,
    UserRoleRelationshipView,
    UserViewSet,
)

router = routers.DefaultRouter(trailing_slash=False)

router.register(r"users", UserViewSet, basename="user")
router.register(r"tenants", TenantViewSet, basename="tenant")
router.register(r"providers", ProviderViewSet, basename="provider")
router.register(r"provider-groups", ProviderGroupViewSet, basename="providergroup")
router.register(r"scans", ScanViewSet, basename="scan")
router.register(r"tasks", TaskViewSet, basename="task")
router.register(r"resources", ResourceViewSet, basename="resource")
router.register(r"findings", FindingViewSet, basename="finding")
router.register(r"roles", RoleViewSet, basename="role")
router.register(
    r"compliance-overviews", ComplianceOverviewViewSet, basename="complianceoverview"
)
router.register(r"overviews", OverviewViewSet, basename="overview")
router.register(r"schedules", ScheduleViewSet, basename="schedule")

tenants_router = routers.NestedSimpleRouter(router, r"tenants", lookup="tenant")
tenants_router.register(
    r"memberships", TenantMembersViewSet, basename="tenant-membership"
)

users_router = routers.NestedSimpleRouter(router, r"users", lookup="user")
users_router.register(r"memberships", MembershipViewSet, basename="user-membership")

urlpatterns = [
    path("tokens", CustomTokenObtainView.as_view(), name="token-obtain"),
    path("tokens/refresh", CustomTokenRefreshView.as_view(), name="token-refresh"),
    path("tokens/switch", CustomTokenSwitchTenantView.as_view(), name="token-switch"),
    path(
        "providers/secrets",
        ProviderSecretViewSet.as_view({"get": "list", "post": "create"}),
        name="providersecret-list",
    ),
    path(
        "providers/secrets/<uuid:pk>",
        ProviderSecretViewSet.as_view(
            {"get": "retrieve", "patch": "partial_update", "delete": "destroy"}
        ),
        name="providersecret-detail",
    ),
    path(
        "tenants/invitations",
        InvitationViewSet.as_view({"get": "list", "post": "create"}),
        name="invitation-list",
    ),
    path(
        "tenants/invitations/<uuid:pk>",
        InvitationViewSet.as_view(
            {"get": "retrieve", "patch": "partial_update", "delete": "destroy"}
        ),
        name="invitation-detail",
    ),
    path(
        "invitations/accept",
        InvitationAcceptViewSet.as_view({"post": "accept"}),
        name="invitation-accept",
    ),
    path(
        "roles/<uuid:pk>/relationships/provider_groups",
        RoleProviderGroupRelationshipView.as_view(
            {"post": "create", "patch": "partial_update", "delete": "destroy"}
        ),
        name="role-provider-groups-relationship",
    ),
    path(
        "users/<uuid:pk>/relationships/roles",
        UserRoleRelationshipView.as_view(
            {"post": "create", "patch": "partial_update", "delete": "destroy"}
        ),
        name="user-roles-relationship",
    ),
    path(
        "provider-groups/<uuid:pk>/relationships/providers",
        ProviderGroupProvidersRelationshipView.as_view(
            {"post": "create", "patch": "partial_update", "delete": "destroy"}
        ),
        name="provider_group-providers-relationship",
    ),
    # re_path(r"^social_accounts/", include("allauth.urls"), name="socialaccount_signup"),
    path("tokens/google", GoogleSocialLoginView.as_view(), name="token-google"),
    path("tokens/github", GithubSocialLoginView.as_view(), name="token-github"),
    # TODOVICTOR Remove
    path("login", LoginPage.as_view(), name="login"),
    path(
        "auth/google/callback",
        GoogleLoginCallback.as_view(),
        name="google_login_callback",
    ),
    path(
        "auth/github/callback",
        GithubLoginCallback.as_view(),
        name="github_login_callback",
    ),
    path("", include(router.urls)),
    path("", include(tenants_router.urls)),
    path("", include(users_router.urls)),
    path("schema", SchemaView.as_view(), name="schema"),
    path("docs", SpectacularRedocView.as_view(url_name="schema"), name="docs"),
]
