from django.contrib import admin
from django.utils.html import format_html
from rest_framework_api_key.admin import APIKeyAdmin

from api.models import (
    APIKey,
    Tenant,
    Role,
)


# The base APIKeyAdmin from djangorestframework-api-key doesn't understand our multi-tenant architecture. Our custom admin adds:
# Tenant visibility: Shows which tenant each API key belongs to
# Tenant filtering: Allows filtering API keys by tenant
# Tenant security: Ensures tenant is properly set during creation
@admin.register(APIKey)
class APIKeyCustomAdmin(APIKeyAdmin):
    """
    Custom admin for API Key model extending djangorestframework-api-key's admin
    with multi-tenancy support.
    """

    list_display = [
        "name",
        "prefix",
        "tenant_name",
        "role_name",
        "is_active_status",
        "expiry_date",
        "last_used_at",
        "created",
    ]
    list_filter = ["tenant", "role", "revoked", "expiry_date", "created"]
    search_fields = ["name", "prefix", "tenant__name", "role__name"]
    readonly_fields = [
        "id",
        "prefix",
        "hashed_key",
        "created",
        "last_used_at",
        "tenant",
    ]

    fieldsets = (
        (None, {"fields": ("name", "tenant", "role")}),
        (
            "Key Information",
            {
                "fields": ("id", "prefix", "hashed_key"),
                "classes": ("collapse",),
            },
        ),
        (
            "Status & Timing",
            {"fields": ("revoked", "expiry_date", "last_used_at", "created")},
        ),
    )

    def tenant_name(self, obj):
        if obj.tenant:
            return obj.tenant.name
        return "-"

    tenant_name.short_description = "Tenant"

    def role_name(self, obj):
        if obj.role:
            return obj.role.name
        return "-"

    role_name.short_description = "Role"

    def is_active_status(self, obj):
        active = obj.is_active()
        if active:
            return format_html('<span style="color: green;">✓ Active</span>')
        else:
            reason = "Revoked" if obj.revoked else "Expired"
            return format_html(f'<span style="color: red;">✗ {reason}</span>')

    is_active_status.short_description = "Status"

    def get_queryset(self, request):
        # Admin users can see all API keys across tenants
        return super().get_queryset(request).select_related("tenant", "role")

    def save_model(self, request, obj, form, change):
        # Ensure tenant is set properly when creating through admin
        if not change and not obj.tenant_id:
            # This should not happen in normal flow, but as a safeguard
            raise ValueError("Tenant must be specified for API key creation")
        super().save_model(request, obj, form, change)


# Register other models with basic admin (if not already registered)
admin.site.register(Tenant)
admin.site.register(Role)

# Customize admin site header
admin.site.site_header = "Prowler API Administration"
admin.site.site_title = "Prowler API Admin"
admin.site.index_title = "Welcome to Prowler API Administration"
