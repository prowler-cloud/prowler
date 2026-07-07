## E2E Schema

Representation of resources in [E2E Networks MyAccount](https://docs.e2enetworks.com/api/myaccount/openapi.yaml). This schema mirrors the [Cartography module format](https://github.com/cartography-cncf/cartography/tree/master/docs/root/modules) for graph-based security analysis and Attack Paths query authoring.

### E2eProject

Representation of an E2E Networks project (tenant scope for all MyAccount resources).

> **Ontology Mapping**: This node has the extra label `Tenant` to enable cross-platform queries for organizational tenants across different systems (e.g., AWSAccount, GCPProject, AzureSubscription).

| Field | Description |
|-------|-------------|
| firstseen | Timestamp of when a sync job discovered this node |
| lastupdated | Timestamp of the last time the node was updated |
| **id** | E2E project ID (`project_id` query parameter) |
| locations | List of deployment regions (e.g. `Delhi`, `Chennai`) |

#### Relationships

- All E2E resources belong to an `E2eProject`.

    ```cypher
    (:E2eProject)-[:RESOURCE]->(:E2eNode,
                                :E2eVpc,
                                :E2eVpcTunnel,
                                :E2eReservedIp,
                                :E2eSecurityGroup,
                                :E2eLoadBalancer,
                                :E2eBlockVolume,
                                :E2eEfs,
                                :E2eEpfs,
                                :E2eDatabaseCluster,
                                :E2eDatabaseInstance)
    ```

### E2eNode

Representation of an E2E Networks compute node ([Nodes API](https://docs.e2enetworks.com/api/myaccount/compute/nodes/)).

| Field | Description |
|-------|-------------|
| firstseen | Timestamp of when a sync job discovered this node |
| lastupdated | Timestamp of the last time the node was updated |
| **id** | Node ID |
| name | Node display name |
| vm_id | Virtual machine identifier used by network and security group APIs |
| status | Node lifecycle status (e.g. `Running`) |
| location | Deployment region (`Delhi`, `Chennai`) |
| public_ip_address | Public IP address if assigned |
| private_ip_address | Private IP address |
| is_vpc_attached | Whether the node is attached to a VPC |
| is_encryption_enabled | Whether encryption at rest is enabled |
| is_accidental_protection | Whether accidental deletion protection is enabled |
| is_node_compliance | Whether compliance monitoring is enabled |
| rescue_mode_status | Rescue mode state (`Enabled` / `Disabled`) |

#### Relationships

- A compute node may be a member of a VPC.

    ```cypher
    (:E2eNode)-[:MEMBER_OF_VPC]->(:E2eVpc)
    ```

- A compute node uses one or more security groups.

    ```cypher
    (:E2eNode)-[:USES]->(:E2eSecurityGroup)
    ```

- Block volumes attach to compute nodes.

    ```cypher
    (:E2eBlockVolume)-[:ATTACHED_TO]->(:E2eNode)
    ```

- Reserved or floating IPs attach to compute nodes.

    ```cypher
    (:E2eReservedIp)-[:ATTACHED_TO]->(:E2eNode)
    ```

### E2eVpc

Representation of an E2E Networks VPC ([VPC API](https://docs.e2enetworks.com/api/myaccount/network/vpc/)).

| Field | Description |
|-------|-------------|
| firstseen | Timestamp of when a sync job discovered this node |
| lastupdated | Timestamp of the last time the node was updated |
| **id** | VPC network ID (`network_id`) |
| name | VPC name |
| location | Deployment region |
| ipv4_cidr | IPv4 CIDR block |
| is_active | Whether the VPC is active |
| state | VPC state (e.g. `Active`) |
| vm_count | Number of nodes attached to the VPC |
| gateway_node_id | Gateway node ID for the VPC |
| gateway_public_ip | Public IP of the VPC gateway node |

#### Relationships

- A VPC contains VPC peering tunnels.

    ```cypher
    (:E2eVpc)-[:CONTAINS]->(:E2eVpcTunnel)
    ```

- A VPC gateway is backed by a compute node.

    ```cypher
    (:E2eVpc)-[:GATEWAY_NODE]->(:E2eNode)
    ```

- EFS and EPFS volumes attach to VPCs.

    ```cypher
    (:E2eEfs)-[:ATTACHED_TO_VPC]->(:E2eVpc)
    (:E2eEpfs)-[:ATTACHED_TO_VPC]->(:E2eVpc)
    ```

### E2eVpcTunnel

Representation of an E2E Networks VPC peering tunnel ([VPC Tunnels API](https://docs.e2enetworks.com/api/myaccount/network/vpc/)).

| Field | Description |
|-------|-------------|
| firstseen | Timestamp of when a sync job discovered this node |
| lastupdated | Timestamp of the last time the node was updated |
| **id** | Tunnel ID |
| name | Tunnel name |
| location | Deployment region |
| local_vpc_network_id | Local VPC network ID |
| status | Tunnel status (e.g. `CREATING`, `ACTIVE`) |
| is_peer_vpc_external | Whether the peer VPC is external to the account |

#### Relationships

- A VPC tunnel peers two VPCs.

    ```cypher
    (:E2eVpcTunnel)-[:PEERS_WITH]->(:E2eVpc)
    (:E2eVpc)-[:PEERS_WITH]->(:E2eVpc)
    ```

### E2eReservedIp

Representation of a reserved, public, addon, or floating IP ([Reserve IP API](https://docs.e2enetworks.com/api/myaccount/network/reserve-ip/)).

| Field | Description |
|-------|-------------|
| firstseen | Timestamp of when a sync job discovered this node |
| lastupdated | Timestamp of the last time the node was updated |
| **id** | Reserve IP ID |
| ip_address | IP address |
| location | Deployment region |
| status | Attachment status (e.g. `Attached`) |
| reserved_type | IP type (`FloatingIP`, `PublicIP`, `AddonIP`) |
| vm_id | Attached VM ID if applicable |

#### Relationships

- Reserved IPs attach to compute nodes.

    ```cypher
    (:E2eReservedIp)-[:ATTACHED_TO]->(:E2eNode)
    ```

### E2eSecurityGroup

Representation of an E2E Networks security group ([Security Group API](https://docs.e2enetworks.com/api/myaccount/network/security-group/)).

| Field | Description |
|-------|-------------|
| firstseen | Timestamp of when a sync job discovered this node |
| lastupdated | Timestamp of the last time the node was updated |
| **id** | Security group ID |
| name | Security group name |
| location | Deployment region |
| is_default | Whether this is the default security group |
| is_all_traffic_rule | Whether an allow-all-traffic rule is present |
| description | Security group description |

#### Relationships

- Security groups attach to compute nodes.

    ```cypher
    (:E2eSecurityGroup)-[:ATTACHED_TO]->(:E2eNode)
    ```

- Security groups may attach to load balancers.

    ```cypher
    (:E2eSecurityGroup)-[:ATTACHED_TO]->(:E2eLoadBalancer)
    ```

### E2eLoadBalancer

Representation of an E2E Networks load balancer appliance ([Appliances API](https://docs.e2enetworks.com/api/myaccount/compute/load-balancer/)).

| Field | Description |
|-------|-------------|
| firstseen | Timestamp of when a sync job discovered this node |
| lastupdated | Timestamp of the last time the node was updated |
| **id** | Load balancer appliance ID |
| name | Load balancer name |
| location | Deployment region |
| status | Appliance status |
| lb_mode | Load balancer mode (e.g. ALB HTTPS) |
| ssl_certificate_id | SSL certificate ID for HTTPS listeners |
| bitninja_enabled | Whether BitNinja protection is enabled |
| public_ip | Public IP address |

#### Relationships

- Load balancers route traffic to backend nodes.

    ```cypher
    (:E2eLoadBalancer)-[:BACKEND]->(:E2eNode)
    ```

### E2eBlockVolume

Representation of an E2E Networks block storage volume ([Block Storage API](https://docs.e2enetworks.com/api/myaccount/storage/block-storage/)).

| Field | Description |
|-------|-------------|
| firstseen | Timestamp of when a sync job discovered this node |
| lastupdated | Timestamp of the last time the node was updated |
| **id** | Block volume ID (`block_id`) |
| name | Volume name |
| location | Deployment region |
| status | Volume status (e.g. `Available`) |
| size_string | Human-readable volume size |
| is_attached | Whether the volume is attached to a node |

#### Relationships

- Block volumes attach to compute nodes.

    ```cypher
    (:E2eBlockVolume)-[:ATTACHED_TO]->(:E2eNode)
    ```

### E2eEfs

Representation of an E2E Networks shared file system (SFS / EFS) ([SFS API](https://docs.e2enetworks.com/api/myaccount/storage/parallel-file-storage/)).

| Field | Description |
|-------|-------------|
| firstseen | Timestamp of when a sync job discovered this node |
| lastupdated | Timestamp of the last time the node was updated |
| **id** | SFS volume ID |
| name | Volume name |
| location | Deployment region |
| status | Volume status |
| vpc_id | Attached VPC ID |
| is_backup_enabled | Whether backup is enabled |
| is_all_vpc_resources_allowed | Whether all VPC resources can access the volume |

#### Relationships

- EFS volumes attach to VPCs.

    ```cypher
    (:E2eEfs)-[:ATTACHED_TO_VPC]->(:E2eVpc)
    ```

### E2eEpfs

Representation of an E2E Networks elastic parallel file system (EPFS).

| Field | Description |
|-------|-------------|
| firstseen | Timestamp of when a sync job discovered this node |
| lastupdated | Timestamp of the last time the node was updated |
| **id** | EPFS volume ID |
| name | Volume name |
| location | Deployment region |
| vpc_network_id | Attached VPC network ID |
| deleted | Whether the volume is marked deleted |

#### Relationships

- EPFS volumes attach to VPCs.

    ```cypher
    (:E2eEpfs)-[:ATTACHED_TO_VPC]->(:E2eVpc)
    ```

### E2eDatabaseCluster

Representation of an E2E Networks DBaaS cluster ([RDS API](https://docs.e2enetworks.com/api/myaccount/database/rds/)).

| Field | Description |
|-------|-------------|
| firstseen | Timestamp of when a sync job discovered this node |
| lastupdated | Timestamp of the last time the node was updated |
| **id** | Cluster ID |
| name | Cluster name |
| location | Deployment region |
| status | Cluster status (e.g. `RUNNING`) |
| software_name | Database engine name (e.g. `MySQL`, `PostgreSQL`) |
| software_version | Database engine version |
| backup_enabled | Whether automated backup is enabled |
| master_ssl_enabled | Whether SSL is enabled on the master node |
| master_has_public_ip | Whether the master node has a public IP |

#### Relationships

- A database cluster has one or more database instances.

    ```cypher
    (:E2eDatabaseCluster)-[:HAS_INSTANCE]->(:E2eDatabaseInstance)
    ```

### E2eDatabaseInstance

Representation of a master or replica instance within an E2E Networks DBaaS cluster.

| Field | Description |
|-------|-------------|
| firstseen | Timestamp of when a sync job discovered this node |
| lastupdated | Timestamp of the last time the node was updated |
| **id** | Instance ID |
| name | Instance node name |
| cluster_id | Parent cluster ID |
| location | Deployment region |
| role | Instance role (`master` or `replica`) |
| public_ip_address | Public IP address if assigned |
| ssl_enabled | Whether SSL is enabled |
| username | Database admin username |

#### Relationships

- Database instances belong to a cluster.

    ```cypher
    (:E2eDatabaseCluster)-[:HAS_INSTANCE]->(:E2eDatabaseInstance)
    ```
