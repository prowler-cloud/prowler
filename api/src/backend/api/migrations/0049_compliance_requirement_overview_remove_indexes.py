from django.contrib.postgres.operations import RemoveIndexConcurrently
from django.db import migrations


class Migration(migrations.Migration):

    atomic = False

    dependencies = [
        ("api", "0048_api_key"),
    ]

    operations = [
        RemoveIndexConcurrently(
            model_name="compliancerequirementoverview",
            name="cro_scan_comp_reg_idx",
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
