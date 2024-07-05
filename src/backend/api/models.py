from django.db import models


class TestModel(models.Model):
    """To delete.

    Use this model for development/testing purposes.
    """

    name = models.CharField(max_length=100)
