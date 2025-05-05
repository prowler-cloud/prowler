import json
from prowler.lib.check.models import Check, Check_Report_IONOS
from prowler.providers.ionos.services.objectstorage.objectstorage_client import ionos_objectstorage_client
from prowler.lib.logger import logger

class objectstorage_bucket_public_access(Check):
    def execute(self):
        findings = []
        
        buckets = ionos_objectstorage_client.get_all_buckets()
        
        for bucket in buckets:
            logger.info("Checking bucket: %s", bucket["Name"])
            report = Check_Report_IONOS(self.metadata())
            report.resource_id = bucket["Name"]
            report.resource_name = bucket["Name"]

            is_public = False
            
            bucket_acl = ionos_objectstorage_client.get_bucket_acl(bucket["Name"])
            
            if bucket_acl:
                for grant in bucket_acl.get("Grants", []):
                    grantee = grant.get("Grantee", {})
                    if grantee.get("URI") == "http://acs.amazonaws.com/groups/global/AllUsers":
                        is_public = True
                        break
            
            if is_public:
                report.status = "FAIL"
                report.status_extended = (
                    f"Bucket {report.resource_name} (ID: {report.resource_id}) "
                    f"has public access enabled"
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Bucket {report.resource_name} (ID: {report.resource_id}) "
                    f"does not have public access"
                )
            
            bucket_details = {
                "name": bucket["Name"],
                "is_public": is_public,
                "creation_date": str(bucket.get("CreationDate", "N/A"))
            }
            report.resource_details = json.dumps(bucket_details)
            findings.append(report)
            
        return findings