from django.contrib.postgres.operations import RemoveIndexConcurrently
from django.db import migrations


class Migration(migrations.Migration):
    atomic = False

    dependencies = [
        ("api", "0056_remove_provider_unique_provider_uids_and_more"),
    ]

    operations = [
        RemoveIndexConcurrently(
            model_name="compliancerequirementoverview",
            name="cro_tenant_scan_idx",
        ),
        RemoveIndexConcurrently(
            model_name="compliancerequirementoverview",
            name="cro_scan_comp_idx",
        ),
        RemoveIndexConcurrently(
            model_name="compliancerequirementoverview",
            name="cro_scan_comp_req_idx",
        ),
        RemoveIndexConcurrently(
            model_name="compliancerequirementoverview",
            name="cro_scan_comp_req_reg_idx",
        ),
    ]
