from rest_framework import serializers
from .models import Account, CloudAccount, Audit


class AccountSerializer(serializers.ModelSerializer):
    class Meta:
        model = Account
        fields = "__all__"


class CloudAccountSerializer(serializers.ModelSerializer):
    class Meta:
        model = CloudAccount
        fields = "__all__"


class AuditSerializer(serializers.ModelSerializer):
    account_id = serializers.SerializerMethodField()

    class Meta:
        model = Audit
        fields = ['id', 'audit_complete', 'inserted_at', 'updated_at', 'audit_duration', 'account_id']

    def get_account_id(self, obj):
        return obj.aws_account_id.account_id.id
