from django.db import migrations

import api.db_utils


class Migration(migrations.Migration):
    dependencies = [
        ("api", "0082_backfill_finding_group_summaries"),
    ]

    operations = [
        migrations.AlterField(
            model_name="provider",
            name="provider",
            field=api.db_utils.ProviderEnumField(
                choices=[
                    ("aws", "AWS"),
                    ("azure", "Azure"),
                    ("gcp", "GCP"),
                    ("kubernetes", "Kubernetes"),
                    ("m365", "M365"),
                    ("github", "GitHub"),
                    ("mongodbatlas", "MongoDB Atlas"),
                    ("iac", "IaC"),
                    ("oraclecloud", "Oracle Cloud Infrastructure"),
                    ("alibabacloud", "Alibaba Cloud"),
                    ("cloudflare", "Cloudflare"),
                    ("openstack", "OpenStack"),
                    ("image", "Image"),
                ],
                default="aws",
            ),
        ),
        migrations.RunSQL(
            "ALTER TYPE provider ADD VALUE IF NOT EXISTS 'image';",
            reverse_sql=migrations.RunSQL.noop,
        ),
    ]
