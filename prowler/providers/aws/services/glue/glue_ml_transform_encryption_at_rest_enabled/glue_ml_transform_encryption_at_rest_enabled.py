from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.glue.glue_client import glue_client

class glue_ml_transform_encryption_at_rest_enabled(Check):

    def execute(self):
    
        for transform in glue_client.transforms():
            report = Check_Report_AWS(self.metadata())
            report.name = transform.name
            report.id = transform.id
            for report.key, report.value in report.transform.transform_encryption.items():
                pass
