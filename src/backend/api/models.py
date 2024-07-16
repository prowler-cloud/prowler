from django.db import models
import uuid


class Base(models.Model):
    """
    Abstract base model class that provides common fields for all models.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    inserted_at = models.DateTimeField(auto_now_add=True, editable=False)
    updated_at = models.DateTimeField(auto_now=True, editable=False)

    class Meta:
        abstract = True


class Tenant(Base):
    """
    The Tenant is the basic grouping in the system. It is used to separate data between customers.
    """

    name = models.CharField(max_length=100)


class TestModel(models.Model):
    """To delete.

    Use this model for development/testing purposes.
    """

    name = models.CharField(max_length=100)
