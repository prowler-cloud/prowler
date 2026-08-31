import json

from api.db_router import MainRouter
from cryptography.fernet import Fernet, InvalidToken
from django.conf import settings
from django.db import migrations, models
from django.db.models.fields.json import KeyTextTransform
from django.db.models.functions import Lower


def normalize_jira_domains(apps, schema_editor):
    Integration = apps.get_model("api", "Integration")
    cipher = Fernet(settings.SECRETS_ENCRYPTION_KEY.encode())
    integrations = list(
        Integration.objects.using(MainRouter.admin_db)
        .filter(integration_type="jira")
        .only("id", "tenant_id", "configuration", "_credentials")
    )

    seen_sites = {}
    for integration in integrations:
        encrypted_credentials = integration._credentials
        if isinstance(encrypted_credentials, memoryview):
            encrypted_credentials = encrypted_credentials.tobytes()
        elif isinstance(encrypted_credentials, str):
            encrypted_credentials = encrypted_credentials.encode()

        try:
            credentials = json.loads(cipher.decrypt(encrypted_credentials).decode())
        except (InvalidToken, TypeError, ValueError, json.JSONDecodeError) as error:
            raise RuntimeError(
                f"Cannot read Jira credentials for integration {integration.id}."
            ) from error

        configuration = dict(integration.configuration or {})
        domain = credentials.get("domain") or configuration.get("domain")
        if not isinstance(domain, str) or not domain.strip():
            raise RuntimeError(
                f"Jira integration {integration.id} does not have a valid site domain."
            )

        canonical_domain = domain.strip().lower()
        site_identity = (str(integration.tenant_id), canonical_domain)
        existing_id = seen_sites.get(site_identity)
        if existing_id is not None:
            raise RuntimeError(
                "Duplicate Jira integrations use site "
                f"{canonical_domain!r} for tenant {integration.tenant_id}: "
                f"{existing_id} and {integration.id}."
            )
        seen_sites[site_identity] = integration.id

        configuration["domain"] = canonical_domain
        credentials["domain"] = canonical_domain
        integration.configuration = configuration
        integration._credentials = cipher.encrypt(json.dumps(credentials).encode())

    if integrations:
        Integration.objects.using(MainRouter.admin_db).bulk_update(
            integrations,
            ["configuration", "_credentials"],
            batch_size=500,
        )


class Migration(migrations.Migration):
    dependencies = [
        ("api", "0099_jira_issues_indexes"),
    ]

    operations = [
        migrations.RunPython(
            normalize_jira_domains,
            reverse_code=migrations.RunPython.noop,
        ),
        migrations.AddConstraint(
            model_name="integration",
            constraint=models.UniqueConstraint(
                models.F("tenant_id"),
                Lower(KeyTextTransform("domain", "configuration")),
                condition=models.Q(("integration_type", "jira")),
                name="unique_jira_site_per_tenant",
            ),
        ),
    ]
