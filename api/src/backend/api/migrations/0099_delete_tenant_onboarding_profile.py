from django.db import migrations


class Migration(migrations.Migration):
    # The onboarding profile step was reverted after 0098 had been merged, so
    # the table goes away through a new migration rather than by deleting 0098.
    dependencies = [
        ("api", "0098_tenant_onboarding_profile"),
    ]

    operations = [
        migrations.DeleteModel(
            name="TenantOnboardingProfile",
        ),
    ]
