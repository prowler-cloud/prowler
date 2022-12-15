from copy import deepcopy

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.ec2.ec2_client import ec2_client
from prowler.providers.aws.services.ec2.lib.security_groups import check_security_group
from prowler.providers.aws.services.emr.emr_client import emr_client
from prowler.providers.aws.services.emr.emr_service import ClusterStatus


class emr_cluster_publicly_accesible(Check):
    def execute(self):
        findings = []
        for cluster in emr_client.clusters.values():
            if cluster.status not in (
                ClusterStatus.TERMINATED,
                ClusterStatus.TERMINATED_WITH_ERRORS,
            ):
                report = Check_Report_AWS(self.metadata())
                report.region = cluster.region
                report.resource_id = cluster.id
                report.resource_arn = cluster.arn

                report.status = "PASS"
                report.status_extended = (
                    f"EMR Cluster {cluster.id} is not publicly accessible"
                )
                # If EMR cluster is Public, it is required to check
                # their Security Groups for the Master,
                # the Slaves and the additional ones
                if cluster.public:

                    # Check Public Master Security Groups
                    master_node_sg_groups = deepcopy(
                        cluster.master.additional_security_groups_id
                    )
                    master_node_sg_groups.append(cluster.master.security_group_id)

                    master_public_security_groups = []
                    for master_sg in master_node_sg_groups:
                        master_sg_public = False
                        for sg in ec2_client.security_groups:
                            if sg.id == master_sg:
                                for ingress_rule in sg.ingress_rules:
                                    if check_security_group(ingress_rule, -1):
                                        master_sg_public = True
                                        break
                            if master_sg_public:
                                master_public_security_groups.append(sg.id)
                                break

                    # Check Public Slave Security Groups
                    slave_node_sg_groups = deepcopy(
                        cluster.slave.additional_security_groups_id
                    )
                    slave_node_sg_groups.append(cluster.slave.security_group_id)

                    slave_public_security_groups = []
                    for slave_sg in slave_node_sg_groups:
                        slave_sg_public = False
                        for sg in ec2_client.security_groups:
                            if sg.id == slave_sg:
                                for ingress_rule in sg.ingress_rules:
                                    if check_security_group(ingress_rule, -1):
                                        slave_sg_public = True
                                        break
                            if slave_sg_public:
                                slave_public_security_groups.append(sg.id)
                                break

                    if master_public_security_groups or slave_public_security_groups:
                        report.status = "FAIL"
                        report.status_extended = f"EMR Cluster {cluster.id} is publicly accessible through the following Security Groups:"
                        report.status_extended += (
                            f" Master Node {master_public_security_groups}"
                            if master_public_security_groups
                            else ""
                        )
                        report.status_extended += (
                            f" Slaves Nodes {slave_public_security_groups}"
                            if slave_public_security_groups
                            else ""
                        )

                    findings.append(report)

        return findings
