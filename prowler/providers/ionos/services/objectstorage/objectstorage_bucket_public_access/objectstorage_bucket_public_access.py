import json
from prowler.lib.check.models import Check, Check_Report_IONOS
from prowler.providers.ionos.services.objectstorage.objectstorage_client import ionos_objectstorage_client
from prowler.lib.logger import logger

class objectstorage_bucket_public_access(Check):
    def execute(self):
        findings = []
        
        buckets = ionos_objectstorage_client.get_buckets_by_region("eu-south-2")

        #print(len(buckets))
        
        for bucket in buckets:
            logger.info("Checking bucket: %s", bucket["Name"])
            report = Check_Report_IONOS(self.metadata())
            report.resource_id = bucket["Name"]
            report.resource_name = bucket["Name"]

            is_public = False
            
            bucket_acl = ionos_objectstorage_client.get_bucket_acl(bucket["Name"])

            #print(f"Bucket ACL: {bucket_acl}")
            
            if bucket_acl:
                for grant in bucket_acl.get("Grants", []):
                    grantee = grant.get("Grantee", {})
                    grantee_type = grantee.get("Type", "").lower()
                    permission = grant.get("Permission", "")

                    # Check for different types of public access
                    if (
                        grantee_type == "group" or 
                        grantee_type == "anonymous" or
                        grantee.get("URI") in [
                            "http://acs.amazonaws.com/groups/global/AllUsers",
                            "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"
                        ]
                    ):
                        logger.warning(
                            f"Bucket {bucket['Name']} has public access - "
                            f"Type: {grantee_type}, Permission: {permission}"
                        )
                        is_public = True
                        break
            
            if is_public:
                report.status = "FAIL"
                report.status_extended = (
                    f"Bucket {report.resource_name} has public access enabled with "
                    f"permission: {permission}"
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Bucket {report.resource_name} is properly secured with "
                    f"no public access"
                )
            
            bucket_details = {
                "name": bucket["Name"],
                "is_public": is_public,
                "acl": bucket_acl,  # Include full ACL for reference
                "creation_date": str(bucket.get("CreationDate", "N/A"))
            }
            report.resource_details = json.dumps(bucket_details)
            findings.append(report)
        
        return findings