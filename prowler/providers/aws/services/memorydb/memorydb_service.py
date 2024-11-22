from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.aws.lib.service.service import AWSService


class MemoryDB(AWSService):
    def __init__(self, provider):
        # Call AWSService's __init__
        super().__init__(__class__.__name__, provider)
        self.clusters = {}
        self.__threading_call__(self._describe_clusters)

    def _describe_clusters(self, regional_client):
        logger.info("MemoryDB - Describe Clusters...")
        try:
            describe_clusters_paginator = regional_client.get_paginator(
                "describe_clusters"
            )
            for page in describe_clusters_paginator.paginate():
                for cluster in page["Clusters"]:
                    try:
                        arn = cluster["ARN"]
                        if not self.audit_resources or (
                            is_resource_filtered(arn, self.audit_resources)
                        ):
                            self.clusters[arn] = Cluster(
                                name=cluster["Name"],
                                arn=arn,
                                number_of_shards=cluster["NumberOfShards"],
                                engine=cluster["Engine"],
                                engine_version=cluster["EngineVersion"],
                                engine_patch_version=cluster["EnginePatchVersion"],
                                multi_az=cluster.get("AvailabilityMode", "singleaz"),
                                region=regional_client.region,
                                security_groups=[
                                    sg["SecurityGroupId"]
                                    for sg in cluster["SecurityGroups"]
                                    if sg["Status"] == "active"
                                ],
                                tls_enabled=cluster["TLSEnabled"],
                                auto_minor_version_upgrade=cluster[
                                    "AutoMinorVersionUpgrade"
                                ],
                                snapshot_limit=cluster["SnapshotRetentionLimit"],
                            )
                    except Exception as error:
                        logger.error(
                            f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                        )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class Cluster(BaseModel):
    name: str
    arn: str
    number_of_shards: int
    engine: str
    engine_version: str
    engine_patch_version: str
    multi_az: str
    region: str
    security_groups: list[str] = []
    tls_enabled: bool
    auto_minor_version_upgrade: bool
    snapshot_limit: int
