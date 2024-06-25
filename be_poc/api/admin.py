from django.contrib import admin
from .models import Account, CloudAccount, Audit

admin.site.register(Account)
admin.site.register(CloudAccount)
admin.site.register(Audit)
