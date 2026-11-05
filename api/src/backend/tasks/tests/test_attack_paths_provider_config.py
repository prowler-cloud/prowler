from tasks.jobs.attack_paths.provider_config import AWS_NORMALIZED_LISTS
from tasks.jobs.attack_paths.sync import _build_catalog_index, _node_to_sync_dict


def test_aws_vpc_endpoint_id_lists_are_normalized():
    catalog = _build_catalog_index(AWS_NORMALIZED_LISTS)
    record = {
        "element_id": "node-1",
        "labels": ["AWSVpcEndpoint"],
        "props": {
            "id": "vpce-123",
            "route_table_ids": ["rtb-1"],
            "network_interface_ids": ["eni-1"],
            "subnet_ids": ["subnet-1"],
        },
    }

    _, parent, children, rels = _node_to_sync_dict(record, "provider-id", catalog)

    assert parent["props"] == {"id": "vpce-123"}
    assert {child["_child_label"] for child in children} == {
        "AWSVpcEndpointRouteTableIdsItem",
        "AWSVpcEndpointNetworkInterfaceIdsItem",
        "AWSVpcEndpointSubnetIdsItem",
    }
    assert {rel["rel_type"] for rel in rels} == {
        "HAS_ROUTE_TABLE_IDS",
        "HAS_NETWORK_INTERFACE_IDS",
        "HAS_SUBNET_IDS",
    }
