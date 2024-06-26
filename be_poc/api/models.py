import uuid

from django.db import models


class Account(models.Model):
    class Meta:
        db_table = "accounts"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=255)
    inserted_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    aws_account_id = models.CharField(max_length=255)
    scan_window_start_at = models.DateTimeField()

    def __str__(self):
        return f"{self.name} - {self.id}"


class CloudAccount(models.Model):
    class Meta:
        db_table = "cloud_accounts"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    account_id = models.OneToOneField(
        Account, on_delete=models.CASCADE, db_column="account_id", to_field="id"
    )
    type = models.CharField(max_length=255)
    groups = models.JSONField(default=list)
    resources = models.IntegerField(default=0)
    enable = models.BooleanField()
    alias = models.CharField(max_length=255, null=True)
    connected = models.BooleanField(default=False)
    provider_id = models.CharField(max_length=255)
    inserted_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.id} ({self.provider_id})"


class Audit(models.Model):
    class Meta:
        db_table = "audits"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    aws_account_id = models.OneToOneField(
        CloudAccount, on_delete=models.CASCADE, db_column="aws_account_id", to_field="account_id"
    )
    audit_complete = models.BooleanField(default=True)
    inserted_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    audit_duration = models.DurationField()

    def __str__(self):
        return f"{self.id} - {self.aws_account_id}"
