
import { tool } from "@opencode-ai/plugin"

const SKILL = `
---
name: django-drf
description: Django REST Framework patterns. ViewSets, Serializers, Filters, permissions.
license: MIT
---

## When to use this skill

Use this skill when building REST APIs with Django REST Framework.

## ViewSet Pattern

\`\`\`python
from rest_framework import viewsets, status
from rest_framework.response import Response
from rest_framework.decorators import action

class UserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    filterset_class = UserFilter
    permission_classes = [IsAuthenticated]

    def get_serializer_class(self):
        if self.action == "create":
            return UserCreateSerializer
        if self.action in ["update", "partial_update"]:
            return UserUpdateSerializer
        return UserSerializer

    @action(detail=True, methods=["post"])
    def activate(self, request, pk=None):
        user = self.get_object()
        user.is_active = True
        user.save()
        return Response({"status": "activated"})
\`\`\`

## Serializer Patterns

\`\`\`python
from rest_framework import serializers

# Read Serializer
class UserSerializer(serializers.ModelSerializer):
    full_name = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = ["id", "email", "full_name", "created_at"]
        read_only_fields = ["id", "created_at"]

    def get_full_name(self, obj):
        return f"{obj.first_name} {obj.last_name}"

# Create Serializer
class UserCreateSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ["email", "password", "first_name", "last_name"]

    def create(self, validated_data):
        password = validated_data.pop("password")
        user = User(**validated_data)
        user.set_password(password)
        user.save()
        return user
\`\`\`

## Filters

\`\`\`python
from django_filters import rest_framework as filters

class UserFilter(filters.FilterSet):
    email = filters.CharFilter(lookup_expr="icontains")
    is_active = filters.BooleanFilter()
    created_after = filters.DateTimeFilter(field_name="created_at", lookup_expr="gte")

    class Meta:
        model = User
        fields = ["email", "is_active"]
\`\`\`

## Permissions

\`\`\`python
from rest_framework.permissions import BasePermission

class IsOwner(BasePermission):
    def has_object_permission(self, request, view, obj):
        return obj.owner == request.user
\`\`\`

## URL Routing

\`\`\`python
from rest_framework.routers import DefaultRouter

router = DefaultRouter()
router.register(r"users", UserViewSet, basename="user")

urlpatterns = [
    path("api/v1/", include(router.urls)),
]
\`\`\`

## Commands

\`\`\`bash
python manage.py runserver
python manage.py makemigrations
python manage.py migrate
\`\`\`

## Keywords
django, drf, rest framework, viewset, serializer, api
`;

export default tool({
  description: SKILL,
  args: {
    topic: tool.schema.string().describe("Topic: viewset, serializer, filter, permission, pagination"),
  },
  async execute(args) {
    const topic = args.topic.toLowerCase();

    if (topic.includes("viewset") || topic.includes("view")) {
      return `
## DRF ViewSet

\`\`\`python
class ItemViewSet(viewsets.ModelViewSet):
    queryset = Item.objects.all()
    serializer_class = ItemSerializer
    filterset_class = ItemFilter

    def get_serializer_class(self):
        if self.action == "create":
            return ItemCreateSerializer
        return ItemSerializer

    @action(detail=True, methods=["post"])
    def publish(self, request, pk=None):
        item = self.get_object()
        item.published = True
        item.save()
        return Response({"status": "published"})
\`\`\`
      `.trim();
    }

    if (topic.includes("serializer")) {
      return `
## DRF Serializers

\`\`\`python
# Read
class ItemSerializer(serializers.ModelSerializer):
    class Meta:
        model = Item
        fields = ["id", "name", "created_at"]
        read_only_fields = ["id", "created_at"]

# Create
class ItemCreateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Item
        fields = ["name", "description"]

    def create(self, validated_data):
        validated_data["owner"] = self.context["request"].user
        return super().create(validated_data)
\`\`\`
      `.trim();
    }

    return `
## DRF Quick Reference

1. **ViewSets**: ModelViewSet with get_serializer_class()
2. **Serializers**: Separate Read/Create/Update serializers
3. **Filters**: FilterSet with django-filter
4. **Permissions**: Custom BasePermission classes
5. **Routing**: DefaultRouter with register()

Topics: viewset, serializer, filter, permission, pagination
    `.trim();
  },
})
