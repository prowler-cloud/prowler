import json

from api.db_utils import rls_transaction
from cryptography.fernet import Fernet
from django.conf import settings
from django.db import migrations


def remove_oraclecloud_secret_regions(apps, schema_editor):
    Tenant = apps.get_model("api", "Tenant")
    ProviderSecret = apps.get_model("api", "ProviderSecret")
    db_alias = schema_editor.connection.alias
    fernet = Fernet(settings.SECRETS_ENCRYPTION_KEY.encode())

    for tenant in Tenant.objects.using(db_alias).all().iterator():
        with rls_transaction(str(tenant.id), using=db_alias):
            provider_secrets = ProviderSecret._base_manager.using(db_alias).filter(
                provider__provider="oraclecloud"
            )

            for provider_secret in provider_secrets.iterator():
                encrypted_secret = provider_secret._secret
                if isinstance(encrypted_secret, memoryview):
                    encrypted_secret = encrypted_secret.tobytes()
                elif isinstance(encrypted_secret, str):
                    encrypted_secret = encrypted_secret.encode()

                secret = json.loads(fernet.decrypt(encrypted_secret).decode())
                if "region" not in secret and "regions" not in secret:
                    continue

                secret.pop("region", None)
                secret.pop("regions", None)
                provider_secret._secret = fernet.encrypt(json.dumps(secret).encode())
                provider_secret.save(update_fields=["_secret"], using=db_alias)


class Migration(migrations.Migration):
    dependencies = [
        ("api", "0096_attack_paths_scan_is_migrated"),
    ]

    operations = [
        migrations.RunPython(
            remove_oraclecloud_secret_regions,
            reverse_code=migrations.RunPython.noop,
        ),
    ]
