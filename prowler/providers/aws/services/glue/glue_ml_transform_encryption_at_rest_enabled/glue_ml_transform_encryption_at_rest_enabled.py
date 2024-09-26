from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.glue.glue_client import glue_client

class glue_ml_transform_encryption_at_rest_enabled(Check):

    def execute(self):
        findings = []
    
        for transform in glue_client.transforms():
           
            report = Check_Report_AWS(self.metadata())
            report.name = transform.name
            report.id = transform.id
            report.transform_encryption = transform.transform_encryption.get('TransformEncryption', {}).get('MlUserDataEncryption',{}).get('MlUserDataEncryptionMode')
            if report.transform_encryption == 'DISABLED':
                report.status = "FAILL"
                report.status_extended =f''

            else:
                report.status = "PASS"
                report.status_extended =f''
                
            findings.append(report)

        return findings
                    



         
        

                
