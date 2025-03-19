from dataclasses import dataclass
from typing import Any, Optional

@dataclass
class OpenNebulaSessionModel:
    """Class to hold the OpenNebula session information"""
    client: Any # This should be the client object from the OpenNebula SDK
    endpoint: str
    username: str
    auth_token: str

@dataclass
class OpenNebulaIdentityModel:
    """Class to hold the OpenNebula identity information"""
    user_id: str
    user_name: str
    group_ids: list
    group_names: list

@dataclass
class OpenNebulaOutputOptionsModel:
    """Class to hold the OpenNebula output options"""
    endpoint: str
    user_name: str