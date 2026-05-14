# Example: DRF API Security Patterns
# Reference for django-drf skill

import re

from rest_framework import serializers, status, viewsets
from rest_framework.exceptions import NotFound
from rest_framework.permissions import SAFE_METHODS, BasePermission, IsAuthenticated
from rest_framework.throttling import UserRateThrottle


# =============================================================================
# INPUT VALIDATION
# =============================================================================


class ProviderCreateSerializer(serializers.Serializer):
    """Example: Input validation in serializers."""

    uid = serializers.CharField(max_length=255)
    provider = serializers.CharField()

    def validate_uid(self, value):
        """Field-level validation with sanitization."""
        # Sanitize: strip whitespace, normalize
        value = value.strip().lower()
        # Validate format
        if not re.match(r"^[a-z0-9-]+$", value):
            raise serializers.ValidationError(
                "UID must be alphanumeric with hyphens only"
            )
        return value

    def validate(self, attrs):
        """Cross-field validation."""
        if attrs.get("provider") == "aws" and len(attrs.get("uid", "")) != 12:
            raise serializers.ValidationError(
                {"uid": "AWS account ID must be 12 digits"}
            )
        return attrs


# =============================================================================
# PREVENT MASS ASSIGNMENT
# =============================================================================


class UserUpdateSerializer(serializers.ModelSerializer):
    """Example: Explicit field whitelist prevents mass assignment."""

    class Meta:
        # GOOD: Explicit whitelist
        fields = ["name", "email"]
        # BAD: fields = "__all__"       # Exposes is_staff, is_superuser
        # BAD: exclude = ["password"]   # New fields auto-exposed


class ProviderSerializer(serializers.ModelSerializer):
    """Example: Read-only fields for computed/system values."""

    class Meta:
        fields = ["id", "uid", "alias", "connected", "inserted_at"]
        # Cannot be set via API - only read
        read_only_fields = ["id", "connected", "inserted_at"]


# =============================================================================
# OBJECT-LEVEL PERMISSIONS
# =============================================================================


class IsOwnerOrReadOnly(BasePermission):
    """Example: Object-level permission check."""

    def has_object_permission(self, request, view, obj):
        # Read permissions for any authenticated request
        if request.method in SAFE_METHODS:
            return True
        # Write permissions only for owner
        return obj.owner == request.user


class DocumentViewSet(viewsets.ModelViewSet):
    """Example: ViewSet with object-level permissions."""

    permission_classes = [IsAuthenticated, IsOwnerOrReadOnly]


# =============================================================================
# RATE LIMITING (THROTTLING)
# =============================================================================

# In settings.py:
# REST_FRAMEWORK = {
#     "DEFAULT_THROTTLE_CLASSES": [
#         "rest_framework.throttling.AnonRateThrottle",
#         "rest_framework.throttling.UserRateThrottle",
#     ],
#     "DEFAULT_THROTTLE_RATES": {
#         "anon": "100/hour",
#         "user": "1000/hour",
#     },
# }


class BurstRateThrottle(UserRateThrottle):
    """Example: Custom throttle for sensitive endpoints."""

    rate = "10/minute"


class PasswordResetViewSet(viewsets.ViewSet):
    """Example: Per-view throttling for sensitive endpoints."""

    throttle_classes = [BurstRateThrottle]


# =============================================================================
# PREVENT INFORMATION DISCLOSURE
# =============================================================================


class SecureViewSet(viewsets.ModelViewSet):
    """Example: Prevent information disclosure patterns."""

    def get_object(self):
        try:
            return super().get_object()
        except Exception:
            # GOOD: Generic message - doesn't leak internal IDs or tenant info
            raise NotFound("Resource not found")
            # BAD: raise NotFound(f"Provider {pk} not found in tenant {tenant_id}")

    def get_queryset(self):
        # Use 404 not 403 for unauthorized access (prevents enumeration)
        # Filter by tenant - unauthorized users get 404, not 403
        return self.queryset.filter(tenant_id=self.request.tenant_id)


# =============================================================================
# SQL INJECTION PREVENTION
# =============================================================================


def safe_query_examples(user_input):
    """Example: SQL injection prevention patterns."""
    from django.db import connection

    # GOOD: Parameterized via ORM
    # Provider.objects.filter(uid=user_input)
    # Provider.objects.extra(where=["uid = %s"], params=[user_input])

    # GOOD: If raw SQL unavoidable, use parameterized queries
    with connection.cursor() as cursor:
        cursor.execute("SELECT * FROM providers WHERE uid = %s", [user_input])

    # BAD: String interpolation = SQL injection vulnerability
    # Provider.objects.raw(f"SELECT * FROM providers WHERE uid = '{user_input}'")
    # cursor.execute(f"SELECT * FROM providers WHERE uid = '{user_input}'")
