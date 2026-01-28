AVAILABLE_PROVIDERS: list[str] = [
    "aws",
]

ROOT_NODE_LABELS: dict[str, str] = {
    "aws": "AWSAccount",
}

NODE_UID_FIELDS: dict[str, str] = {
    "aws": "arn",
}


def is_provider_available(provider_type: str) -> bool:
    return provider_type in AVAILABLE_PROVIDERS


def get_root_node_label(provider_type: str) -> str:
    return ROOT_NODE_LABELS.get(provider_type, "UnknownProviderAccount")


def get_node_uid_field(provider_type: str) -> str:
    return NODE_UID_FIELDS.get(provider_type, "UnknownProviderUID")
