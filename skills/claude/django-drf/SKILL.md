---
name: django-drf
description: >
  Django REST Framework patterns.
  Trigger: When building REST APIs with Django - ViewSets, Serializers, Filters.
license: Apache-2.0
metadata:
  author: prowler-cloud
  version: "1.0"
---

## ViewSet Pattern

```python
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
```

## Serializer Patterns

```python
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

# Update Serializer
class UserUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ["first_name", "last_name"]
```

## Filters

```python
from django_filters import rest_framework as filters

class UserFilter(filters.FilterSet):
    email = filters.CharFilter(lookup_expr="icontains")
    is_active = filters.BooleanFilter()
    created_after = filters.DateTimeFilter(
        field_name="created_at",
        lookup_expr="gte"
    )
    created_before = filters.DateTimeFilter(
        field_name="created_at",
        lookup_expr="lte"
    )

    class Meta:
        model = User
        fields = ["email", "is_active"]
```

## Permissions

```python
from rest_framework.permissions import BasePermission

class IsOwner(BasePermission):
    def has_object_permission(self, request, view, obj):
        return obj.owner == request.user

class IsAdminOrReadOnly(BasePermission):
    def has_permission(self, request, view):
        if request.method in ["GET", "HEAD", "OPTIONS"]:
            return True
        return request.user.is_staff
```

## Pagination

```python
from rest_framework.pagination import PageNumberPagination

class StandardPagination(PageNumberPagination):
    page_size = 20
    page_size_query_param = "page_size"
    max_page_size = 100

# settings.py
REST_FRAMEWORK = {
    "DEFAULT_PAGINATION_CLASS": "api.pagination.StandardPagination",
}
```

## URL Routing

```python
from rest_framework.routers import DefaultRouter

router = DefaultRouter()
router.register(r"users", UserViewSet, basename="user")
router.register(r"posts", PostViewSet, basename="post")

urlpatterns = [
    path("api/v1/", include(router.urls)),
]
```

## Testing

```python
import pytest
from rest_framework import status
from rest_framework.test import APIClient

@pytest.fixture
def api_client():
    return APIClient()

@pytest.fixture
def authenticated_client(api_client, user):
    api_client.force_authenticate(user=user)
    return api_client

@pytest.mark.django_db
class TestUserViewSet:
    def test_list_users(self, authenticated_client):
        response = authenticated_client.get("/api/v1/users/")
        assert response.status_code == status.HTTP_200_OK

    def test_create_user(self, authenticated_client):
        data = {"email": "new@test.com", "password": "pass123"}
        response = authenticated_client.post("/api/v1/users/", data)
        assert response.status_code == status.HTTP_201_CREATED
```

## Commands

```bash
python manage.py runserver
python manage.py makemigrations
python manage.py migrate
python manage.py createsuperuser
python manage.py shell
```

## Keywords
django, drf, rest framework, viewset, serializer, api, rest api
