import json

from prowler.lib.check.models import Check, Check_Report_IONOS
from prowler.lib.logger import logger
from prowler.providers.ionos.services.objectstorage.objectstorage_client import (
    ionos_objectstorage_client,
)


class objectstorage_bucket_public_access(Check):
    def execute(self):
        findings = []

        buckets = ionos_objectstorage_client.get_all_buckets()

        for bucket in buckets:
            logger.info("Checking bucket: %s", bucket)
            logger.info("Bucket Region: %s", buckets[bucket])

            bucket_data = {
                "name": bucket,
                "region": buckets[bucket],
            }

            report = Check_Report_IONOS(self.metadata(), resource=bucket_data)
            report.resource_id = bucket
            report.resource_name = bucket

            is_public = False
            public_permission = ""

            bucket_acl = ionos_objectstorage_client.get_bucket_acl(bucket)

            if bucket_acl:
                for grant in bucket_acl.get("Grants", []):
                    grantee = grant.get("Grantee", {})
                    grantee_type = grantee.get("Type", "").lower()
                    permission = grant.get("Permission", "")

                    if grantee_type in {"group", "anonymous"} or grantee.get("URI") in {
                        "http://acs.amazonaws.com/groups/global/AllUsers",
                        "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
                    }:
                        logger.warning(
                            f"Bucket {bucket} has public access - "
                            f"Type: {grantee_type}, Permission: {permission}"
                        )
                        is_public = True
                        public_permission = permission
                        break

            if is_public:
                report.status = "FAIL"
                report.status_extended = (
                    f"Bucket {report.resource_name} has public access enabled with "
                    f"permission: {public_permission}"
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Bucket {report.resource_name} is properly secured with "
                    f"no public access"
                )

            bucket_details = {
                "name": bucket,
                "is_public": is_public,
                "acl": bucket_acl,
            }
            report.resource_details = json.dumps(bucket_details)
            findings.append(report)

        return findings
