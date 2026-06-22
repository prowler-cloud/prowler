from prowler.providers.e2e.services.database.database_service import (
    DatabaseCluster,
    DatabaseInstance,
)
from prowler.providers.e2e.services.loadbalancer.loadbalancer_service import LoadBalancer
from prowler.providers.e2e.services.network.network_service import (
    ReservedIp,
    Vpc,
    VpcTunnel,
)
from prowler.providers.e2e.services.node.nodes_service import Node
from prowler.providers.e2e.services.securitygroup.securitygroup_service import (
    NodeSecurityGroup,
    SecurityGroupResource,
    SecurityGroupRule,
)
from prowler.providers.e2e.services.storage.storage_service import (
    BlockVolume,
    EfsVolume,
    StorageBucket,
)
from tests.providers.e2e.e2e_fixtures import run_e2e_check


def _database_client_path(check_name: str) -> str:
    return (
        f"prowler.providers.e2e.services.database.{check_name}.{check_name}"
        ".database_client"
    )


def _network_client_path(check_name: str) -> str:
    return (
        f"prowler.providers.e2e.services.network.{check_name}.{check_name}"
        ".network_client"
    )


def _node_client_path(check_name: str) -> str:
    return (
        f"prowler.providers.e2e.services.node.{check_name}.{check_name}.nodes_client"
    )


def _storage_client_path(check_name: str) -> str:
    return (
        f"prowler.providers.e2e.services.storage.{check_name}.{check_name}"
        ".storage_client"
    )


def _loadbalancer_client_path(check_name: str) -> str:
    return (
        f"prowler.providers.e2e.services.loadbalancer.{check_name}.{check_name}"
        ".loadbalancer_client"
    )


def _securitygroup_client_path(check_name: str) -> str:
    return (
        f"prowler.providers.e2e.services.securitygroup.{check_name}.{check_name}"
        ".securitygroup_client"
    )


class TestDatabaseChecks:
    def test_database_cluster_backup_enabled(self):
        check = "database_cluster_backup_enabled"
        resources = [
            DatabaseCluster(
                id="1",
                name="ok",
                location="Delhi",
                backup_enabled=True,
            ),
            DatabaseCluster(
                id="2",
                name="bad",
                location="Delhi",
                backup_enabled=False,
            ),
        ]
        findings = run_e2e_check(
            f"prowler.providers.e2e.services.database.{check}.{check}",
            _database_client_path(check),
            "clusters",
            resources,
        )
        assert len(findings) == 2
        assert findings[0].status == "PASS"
        assert findings[1].status == "FAIL"

    def test_database_cluster_default_admin_username(self):
        check = "database_cluster_default_admin_username"
        resources = [
            DatabaseCluster(
                id="1",
                name="ok",
                location="Delhi",
                master_username="dbadmin",
            ),
            DatabaseCluster(
                id="2",
                name="bad",
                location="Delhi",
                master_username="admin",
            ),
        ]
        findings = run_e2e_check(
            f"prowler.providers.e2e.services.database.{check}.{check}",
            _database_client_path(check),
            "clusters",
            resources,
        )
        assert findings[0].status == "PASS"
        assert findings[1].status == "FAIL"

    def test_database_cluster_ip_whitelist_configured(self):
        check = "database_cluster_ip_whitelist_configured"
        resources = [
            DatabaseCluster(
                id="1",
                name="ok",
                location="Delhi",
                master_has_public_ip=True,
                whitelisted_ips=["203.0.113.0/24"],
            ),
            DatabaseCluster(
                id="2",
                name="bad",
                location="Delhi",
                master_has_public_ip=True,
                whitelisted_ips=[],
            ),
        ]
        findings = run_e2e_check(
            f"prowler.providers.e2e.services.database.{check}.{check}",
            _database_client_path(check),
            "clusters",
            resources,
        )
        assert len(findings) == 2
        assert findings[0].status == "PASS"
        assert findings[1].status == "FAIL"

    def test_database_cluster_public_ip_not_assigned(self):
        check = "database_cluster_public_ip_not_assigned"
        resources = [
            DatabaseCluster(
                id="1",
                name="ok",
                location="Delhi",
                master_has_public_ip=False,
            ),
            DatabaseCluster(
                id="2",
                name="bad",
                location="Delhi",
                master_has_public_ip=True,
            ),
        ]
        findings = run_e2e_check(
            f"prowler.providers.e2e.services.database.{check}.{check}",
            _database_client_path(check),
            "clusters",
            resources,
        )
        assert findings[0].status == "PASS"
        assert findings[1].status == "FAIL"

    def test_database_cluster_running(self):
        check = "database_cluster_running"
        resources = [
            DatabaseCluster(
                id="1",
                name="ok",
                location="Delhi",
                status="RUNNING",
            ),
            DatabaseCluster(
                id="2",
                name="bad",
                location="Delhi",
                status="STOPPED",
            ),
        ]
        findings = run_e2e_check(
            f"prowler.providers.e2e.services.database.{check}.{check}",
            _database_client_path(check),
            "clusters",
            resources,
        )
        assert findings[0].status == "PASS"
        assert findings[1].status == "FAIL"

    def test_database_replica_public_ip_not_assigned(self):
        check = "database_replica_public_ip_not_assigned"
        resources = [
            DatabaseInstance(
                id="1",
                name="ok",
                cluster_id="c1",
                cluster_name="cluster",
                location="Delhi",
                role="replica",
                has_public_ip=False,
            ),
            DatabaseInstance(
                id="2",
                name="bad",
                cluster_id="c1",
                cluster_name="cluster",
                location="Delhi",
                role="replica",
                has_public_ip=True,
            ),
        ]
        findings = run_e2e_check(
            f"prowler.providers.e2e.services.database.{check}.{check}",
            _database_client_path(check),
            "instances",
            resources,
        )
        assert findings[0].status == "PASS"
        assert findings[1].status == "FAIL"


class TestNetworkChecks:
    def test_network_reserveip_floating_ip_unattached(self):
        check = "network_reserveip_floating_ip_unattached"
        resources = [
            ReservedIp(
                reserve_id="1",
                ip_address="1.2.3.4",
                location="Delhi",
                reserved_type="FloatingIP",
                status="Attached",
                floating_ip_attached_nodes_count=1,
            ),
            ReservedIp(
                reserve_id="2",
                ip_address="5.6.7.8",
                location="Delhi",
                reserved_type="FloatingIP",
                status="Available",
                floating_ip_attached_nodes_count=0,
            ),
        ]
        findings = run_e2e_check(
            f"prowler.providers.e2e.services.network.{check}.{check}",
            _network_client_path(check),
            "reserved_ips",
            resources,
        )
        assert findings[0].status == "PASS"
        assert findings[1].status == "FAIL"

    def test_network_reserveip_orphaned_public_ip(self):
        check = "network_reserveip_orphaned_public_ip"
        resources = [
            ReservedIp(
                reserve_id="1",
                ip_address="1.2.3.4",
                location="Delhi",
                reserved_type="PublicIP",
                status="Attached",
                vm_id=123,
            ),
            ReservedIp(
                reserve_id="2",
                ip_address="5.6.7.8",
                location="Delhi",
                reserved_type="PublicIP",
                status="Available",
                vm_id=None,
            ),
        ]
        findings = run_e2e_check(
            f"prowler.providers.e2e.services.network.{check}.{check}",
            _network_client_path(check),
            "reserved_ips",
            resources,
        )
        assert findings[0].status == "PASS"
        assert findings[1].status == "FAIL"

    def test_network_vpc_has_attached_nodes(self):
        check = "network_vpc_has_attached_nodes"
        resources = [
            Vpc(network_id="1", name="ok", location="Delhi", vm_count=2),
            Vpc(network_id="2", name="bad", location="Delhi", vm_count=0),
        ]
        findings = run_e2e_check(
            f"prowler.providers.e2e.services.network.{check}.{check}",
            _network_client_path(check),
            "vpcs",
            resources,
        )
        assert findings[0].status == "PASS"
        assert findings[1].status == "FAIL"

    def test_network_vpc_peering_external_peer_disabled(self):
        check = "network_vpc_peering_external_peer_disabled"
        resources = [
            VpcTunnel(
                id="1",
                name="ok",
                location="Delhi",
                local_vpc_network_id="vpc-1",
                local_vpc_name="vpc",
                is_peer_vpc_external=False,
            ),
            VpcTunnel(
                id="2",
                name="bad",
                location="Delhi",
                local_vpc_network_id="vpc-2",
                local_vpc_name="vpc",
                is_peer_vpc_external=True,
            ),
        ]
        findings = run_e2e_check(
            f"prowler.providers.e2e.services.network.{check}.{check}",
            _network_client_path(check),
            "vpc_tunnels",
            resources,
        )
        assert findings[0].status == "PASS"
        assert findings[1].status == "FAIL"


class TestNodeChecks:
    def test_node_accidental_protection_enabled(self):
        check = "node_accidental_protection_enabled"
        resources = [
            Node(
                id="1",
                name="ok",
                status="Running",
                location="Delhi",
                vm_id="1",
                is_accidental_protection=True,
            ),
            Node(
                id="2",
                name="bad",
                status="Running",
                location="Delhi",
                vm_id="2",
                is_accidental_protection=False,
            ),
        ]
        findings = run_e2e_check(
            f"prowler.providers.e2e.services.node.{check}.{check}",
            _node_client_path(check),
            "nodes",
            resources,
        )
        assert findings[0].status == "PASS"
        assert findings[1].status == "FAIL"

    def test_node_compliance_enabled(self):
        check = "node_compliance_enabled"
        resources = [
            Node(
                id="1",
                name="ok",
                status="Running",
                location="Delhi",
                vm_id="1",
                is_node_compliance=True,
            ),
            Node(
                id="2",
                name="bad",
                status="Running",
                location="Delhi",
                vm_id="2",
                is_node_compliance=False,
            ),
        ]
        findings = run_e2e_check(
            f"prowler.providers.e2e.services.node.{check}.{check}",
            _node_client_path(check),
            "nodes",
            resources,
        )
        assert findings[0].status == "PASS"
        assert findings[1].status == "FAIL"

    def test_node_encryption_enabled(self):
        check = "node_encryption_enabled"
        resources = [
            Node(
                id="1",
                name="ok",
                status="Running",
                location="Delhi",
                vm_id="1",
                is_encryption_enabled=True,
            ),
            Node(
                id="2",
                name="bad",
                status="Running",
                location="Delhi",
                vm_id="2",
                is_encryption_enabled=False,
            ),
        ]
        findings = run_e2e_check(
            f"prowler.providers.e2e.services.node.{check}.{check}",
            _node_client_path(check),
            "nodes",
            resources,
        )
        assert findings[0].status == "PASS"
        assert findings[1].status == "FAIL"

    def test_node_rescue_mode_disabled(self):
        check = "node_rescue_mode_disabled"
        resources = [
            Node(
                id="1",
                name="ok",
                status="Running",
                location="Delhi",
                vm_id="1",
                rescue_mode_status="Disabled",
            ),
            Node(
                id="2",
                name="bad",
                status="Running",
                location="Delhi",
                vm_id="2",
                rescue_mode_status="Enabled",
            ),
        ]
        findings = run_e2e_check(
            f"prowler.providers.e2e.services.node.{check}.{check}",
            _node_client_path(check),
            "nodes",
            resources,
        )
        assert findings[0].status == "PASS"
        assert findings[1].status == "FAIL"

    def test_node_vpc_attached(self):
        check = "node_vpc_attached"
        resources = [
            Node(
                id="1",
                name="ok",
                status="Running",
                location="Delhi",
                vm_id="1",
                is_vpc_attached=True,
            ),
            Node(
                id="2",
                name="bad",
                status="Running",
                location="Delhi",
                vm_id="2",
                is_vpc_attached=False,
            ),
        ]
        findings = run_e2e_check(
            f"prowler.providers.e2e.services.node.{check}.{check}",
            _node_client_path(check),
            "nodes",
            resources,
        )
        assert findings[0].status == "PASS"
        assert findings[1].status == "FAIL"


class TestStorageChecks:
    def test_storage_block_volume_not_orphaned(self):
        check = "storage_block_volume_not_orphaned"
        resources = [
            BlockVolume(
                id="1",
                name="ok",
                location="Delhi",
                is_attached=True,
            ),
            BlockVolume(
                id="2",
                name="bad",
                location="Delhi",
                status="Available",
                is_attached=False,
            ),
        ]
        findings = run_e2e_check(
            f"prowler.providers.e2e.services.storage.{check}.{check}",
            _storage_client_path(check),
            "block_volumes",
            resources,
        )
        assert findings[0].status == "PASS"
        assert findings[1].status == "FAIL"

    def test_storage_bucket_encryption_enabled(self):
        check = "storage_bucket_encryption_enabled"
        resources = [
            StorageBucket(
                id="1",
                name="ok",
                location="Delhi",
                is_encryption_enabled=True,
            ),
            StorageBucket(
                id="2",
                name="bad",
                location="Delhi",
                is_encryption_enabled=False,
            ),
        ]
        findings = run_e2e_check(
            f"prowler.providers.e2e.services.storage.{check}.{check}",
            _storage_client_path(check),
            "buckets",
            resources,
        )
        assert findings[0].status == "PASS"
        assert findings[1].status == "FAIL"

    def test_storage_bucket_lifecycle_configured(self):
        check = "storage_bucket_lifecycle_configured"
        resources = [
            StorageBucket(
                id="1",
                name="ok",
                location="Delhi",
                lifecycle_configuration_status="Configured",
            ),
            StorageBucket(
                id="2",
                name="bad",
                location="Delhi",
                lifecycle_configuration_status="Disabled",
            ),
        ]
        findings = run_e2e_check(
            f"prowler.providers.e2e.services.storage.{check}.{check}",
            _storage_client_path(check),
            "buckets",
            resources,
        )
        assert findings[0].status == "PASS"
        assert findings[1].status == "FAIL"

    def test_storage_bucket_lock_enabled(self):
        check = "storage_bucket_lock_enabled"
        resources = [
            StorageBucket(
                id="1",
                name="ok",
                location="Delhi",
                is_lock_enabled=True,
            ),
            StorageBucket(
                id="2",
                name="bad",
                location="Delhi",
                is_lock_enabled=False,
            ),
        ]
        findings = run_e2e_check(
            f"prowler.providers.e2e.services.storage.{check}.{check}",
            _storage_client_path(check),
            "buckets",
            resources,
        )
        assert findings[0].status == "PASS"
        assert findings[1].status == "FAIL"

    def test_storage_bucket_public_access_disabled(self):
        check = "storage_bucket_public_access_disabled"
        resources = [
            StorageBucket(
                id="1",
                name="ok",
                location="Delhi",
                is_public_access_enabled=False,
            ),
            StorageBucket(
                id="2",
                name="bad",
                location="Delhi",
                is_public_access_enabled=True,
            ),
        ]
        findings = run_e2e_check(
            f"prowler.providers.e2e.services.storage.{check}.{check}",
            _storage_client_path(check),
            "buckets",
            resources,
        )
        assert findings[0].status == "PASS"
        assert findings[1].status == "FAIL"

    def test_storage_bucket_versioning_enabled(self):
        check = "storage_bucket_versioning_enabled"
        resources = [
            StorageBucket(
                id="1",
                name="ok",
                location="Delhi",
                versioning_status="Enabled",
            ),
            StorageBucket(
                id="2",
                name="bad",
                location="Delhi",
                versioning_status="Off",
            ),
        ]
        findings = run_e2e_check(
            f"prowler.providers.e2e.services.storage.{check}.{check}",
            _storage_client_path(check),
            "buckets",
            resources,
        )
        assert findings[0].status == "PASS"
        assert findings[1].status == "FAIL"

    def test_storage_efs_vpc_access_restricted(self):
        check = "storage_efs_vpc_access_restricted"
        resources = [
            EfsVolume(
                id="1",
                name="ok",
                location="Delhi",
                is_all_vpc_resources_allowed=False,
            ),
            EfsVolume(
                id="2",
                name="bad",
                location="Delhi",
                is_all_vpc_resources_allowed=True,
            ),
        ]
        findings = run_e2e_check(
            f"prowler.providers.e2e.services.storage.{check}.{check}",
            _storage_client_path(check),
            "efs_volumes",
            resources,
        )
        assert findings[0].status == "PASS"
        assert findings[1].status == "FAIL"


class TestLoadBalancerChecks:
    def test_loadbalancer_alb_https_uses_ssl_certificate(self):
        check = "loadbalancer_alb_https_uses_ssl_certificate"
        resources = [
            LoadBalancer(
                id="1",
                name="ok",
                location="Delhi",
                lb_mode="HTTPS",
                ssl_certificate_id="cert-1",
            ),
            LoadBalancer(
                id="2",
                name="bad",
                location="Delhi",
                lb_mode="HTTPS",
                ssl_certificate_id=None,
            ),
        ]
        findings = run_e2e_check(
            f"prowler.providers.e2e.services.loadbalancer.{check}.{check}",
            _loadbalancer_client_path(check),
            "load_balancers",
            resources,
        )
        assert findings[0].status == "PASS"
        assert findings[1].status == "FAIL"

    def test_loadbalancer_backend_health_check_enabled(self):
        check = "loadbalancer_backend_health_check_enabled"
        resources = [
            LoadBalancer(
                id="1",
                name="ok",
                location="Delhi",
                lb_mode="HTTP",
                backends=[{"http_check": True}],
            ),
            LoadBalancer(
                id="2",
                name="bad",
                location="Delhi",
                lb_mode="HTTP",
                backends=[{}],
            ),
        ]
        findings = run_e2e_check(
            f"prowler.providers.e2e.services.loadbalancer.{check}.{check}",
            _loadbalancer_client_path(check),
            "load_balancers",
            resources,
        )
        assert findings[0].status == "PASS"
        assert findings[1].status == "FAIL"

    def test_loadbalancer_bitninja_enabled(self):
        check = "loadbalancer_bitninja_enabled"
        resources = [
            LoadBalancer(
                id="1",
                name="ok",
                location="Delhi",
                enable_bitninja=True,
            ),
            LoadBalancer(
                id="2",
                name="bad",
                location="Delhi",
                enable_bitninja=False,
            ),
        ]
        findings = run_e2e_check(
            f"prowler.providers.e2e.services.loadbalancer.{check}.{check}",
            _loadbalancer_client_path(check),
            "load_balancers",
            resources,
        )
        assert findings[0].status == "PASS"
        assert findings[1].status == "FAIL"


class TestSecurityGroupChecks:
    def test_securitygroup_no_all_traffic_rule(self):
        check = "securitygroup_no_all_traffic_rule"
        resources = [
            SecurityGroupResource(
                id="1",
                name="ok",
                location="Delhi",
                is_all_traffic_rule=False,
            ),
            SecurityGroupResource(
                id="2",
                name="bad",
                location="Delhi",
                is_all_traffic_rule=True,
            ),
        ]
        findings = run_e2e_check(
            f"prowler.providers.e2e.services.securitygroup.{check}.{check}",
            _securitygroup_client_path(check),
            "security_groups",
            resources,
        )
        assert findings[0].status == "PASS"
        assert findings[1].status == "FAIL"

    def test_securitygroup_no_inbound_any_all_ports(self):
        check = "securitygroup_no_inbound_any_all_ports"
        permissive_rule = SecurityGroupRule(
            id="1",
            rule_type="inbound",
            protocol_name="all",
            port_range="",
            network="any",
            network_cidr="",
        )
        safe_rule = SecurityGroupRule(
            id="2",
            rule_type="inbound",
            protocol_name="tcp",
            port_range="443",
            network="203.0.113.0/24",
            network_cidr="203.0.113.0/24",
        )
        resources = [
            SecurityGroupResource(
                id="1",
                name="ok",
                location="Delhi",
                rules=[safe_rule],
            ),
            SecurityGroupResource(
                id="2",
                name="bad",
                location="Delhi",
                rules=[permissive_rule],
            ),
        ]
        findings = run_e2e_check(
            f"prowler.providers.e2e.services.securitygroup.{check}.{check}",
            _securitygroup_client_path(check),
            "security_groups",
            resources,
        )
        assert findings[0].status == "PASS"
        assert findings[1].status == "FAIL"

    def test_securitygroup_restrictive_default(self):
        check = "securitygroup_restrictive_default"
        permissive_rule = SecurityGroupRule(
            id="1",
            rule_type="inbound",
            protocol_name="all",
            port_range="",
            network="any",
            network_cidr="",
        )
        resources = [
            NodeSecurityGroup(
                node_id="1",
                node_name="ok-node",
                vm_id="vm-1",
                location="Delhi",
                security_group_id="sg-1",
                name="custom",
                is_default=False,
                rules=[],
            ),
            NodeSecurityGroup(
                node_id="2",
                node_name="bad-node",
                vm_id="vm-2",
                location="Delhi",
                security_group_id="sg-2",
                name="default",
                is_default=True,
                rules=[permissive_rule],
            ),
        ]
        findings = run_e2e_check(
            f"prowler.providers.e2e.services.securitygroup.{check}.{check}",
            _securitygroup_client_path(check),
            "node_security_groups",
            resources,
        )
        assert findings[0].status == "PASS"
        assert findings[1].status == "FAIL"
