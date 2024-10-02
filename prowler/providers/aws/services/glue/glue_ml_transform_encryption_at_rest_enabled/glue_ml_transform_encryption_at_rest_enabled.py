from typing import List
from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.glue.glue_client import glue_client

class glue_ml_transform_encryption_at_rest_enabled(Check):
    def execute(self):
        findings = []

        for crafted_arn, transform in glue_client.ml_transforms.items():
            report = Check_Report_AWS(self.metadata())
            report.resource_id = transform.id
            report.resource_arn = crafted_arn
            report.resource_tags = transform.tags
            report.region = transform.region
            if transform.transform_encryption == "DISABLED":
                report.status = "FAIL"
                report.status_extended = f"Glue ML Transform {transform.name} has encryption DISABLED at rest."
            else:
                report.status = "PASS"
                report.status_extended = f"Glue ML Transform {transform.name} has encryption enabled (SSE-KMS mode) at rest."

            findings.append(report)

        return findings
        

            
                    



         
               
            
            
                

                
