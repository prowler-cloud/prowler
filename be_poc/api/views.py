from rest_framework import generics
from .models import Account, CloudAccount, Audit
from .serializers import AccountSerializer, CloudAccountSerializer, AuditSerializer


class AccountListView(generics.ListAPIView):
    queryset = Account.objects.all()
    serializer_class = AccountSerializer


class CloudAccountListView(generics.ListAPIView):
    serializer_class = CloudAccountSerializer

    def get_queryset(self):
        provider_id = self.kwargs.get('provider_id')
        return CloudAccount.objects.filter(provider_id=provider_id)


class AuditListView(generics.ListAPIView):
    serializer_class = AuditSerializer

    def get_queryset(self):
        queryset = Audit.objects.all()
        account_id = self.request.query_params.get('account_id')
        if account_id:
            queryset = queryset.filter(aws_account_id__account_id=account_id)
        return queryset
