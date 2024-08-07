from datetime import datetime
from typing import Optional

from botocore.client import ClientError
from pydantic import BaseModel
from pympler import asizeof

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.aws.lib.service.service import AWSService
import sys 
import gc 

import dill as pickle
import os
import atexit
from collections import deque
from sys import getsizeof
import tempfile

import boto3
from moto import mock_aws
from memory_profiler import profile
import pdb
import psutil
import os

def check_memory_usage():
    process = psutil.Process(os.getpid())
    memory_info = process.memory_info()
    return memory_info.rss  # Resident Set Size: memory in bytes


class PaginatedList:
    instance_counter = 0

    def __init__(self, page_size=1):
        self.page_size = page_size
        self.file_paths = []
        self.cache = {}
        self.length = 0  # Track the length dynamically
        self.instance_id = PaginatedList.instance_counter
        PaginatedList.instance_counter += 1
        self.temp_dir = tempfile.mkdtemp(prefix=f'paginated_list_{self.instance_id}_', dir='/Users/snaow/repos/prowler')
        atexit.register(self.cleanup)
        
    def _save_page(self, page_data, page_num):
        file_path = os.path.join(self.temp_dir, f'page_{page_num}.pkl')
        with open(file_path, 'wb') as f:
            pickle.dump(page_data, f)
        if page_num >= len(self.file_paths):
            self.file_paths.append(file_path)
        else:
            self.file_paths[page_num] = file_path

    def _load_page(self, page_num):
        if page_num in self.cache:
            return self.cache[page_num]
        with open(self.file_paths[page_num], 'rb') as f:
            page_data = pickle.load(f)
        self.cache[page_num] = page_data
        return page_data

    def __getitem__(self, index):
        if index < 0 or index >= self.length:
            raise IndexError('Index out of range')
        page_num = index // self.page_size
        page_index = index % self.page_size
        page_data = self._load_page(page_num)
        return page_data[page_index]

    def __setitem__(self, index, value):
        if index < 0 or index >= self.length:
            raise IndexError('Index out of range')
        page_num = index // self.page_size
        page_index = index % self.page_size
        page_data = self._load_page(page_num)
        page_data[page_index] = value
        self.cache[page_num] = page_data
        self._save_page(page_data, page_num)

    def __delitem__(self, index):
        if index < 0 or index >= self.length:
            raise IndexError('Index out of range')
        page_num = index // self.page_size
        page_index = index % self.page_size
        page_data = self._load_page(page_num)
        del page_data[page_index]
        self.cache[page_num] = page_data
        self._save_page(page_data, page_num)
        self.length -= 1

        # Shift subsequent elements
        for i in range(index, self.length):
            next_page_num = (i + 1) // self.page_size
            next_page_index = (i + 1) % self.page_size
            if next_page_index == 0:
                self._save_page(page_data, page_num)
                page_num = next_page_num
                page_data = self._load_page(page_num)
            page_data[page_index] = page_data.pop(next_page_index)
            page_index = next_page_index

        # Save the last page
        self._save_page(page_data, page_num)
        
        # Remove the last page if it's empty
        if self.length % self.page_size == 0:
            os.remove(self.file_paths.pop())
            self.cache.pop(page_num, None)

    def __len__(self):
        return self.length

    def __iter__(self):
        for page_num in range(len(self.file_paths)):
            page_data = self._load_page(page_num)
            for item in page_data:
                yield item

    def append(self, value):
        page_num = self.length // self.page_size
        page_index = self.length % self.page_size
        if page_num >= len(self.file_paths):
            self._save_page([], page_num)
        page_data = self._load_page(page_num)
        page_data.append(value)
        self.cache[page_num] = page_data
        self._save_page(page_data, page_num)
        self.length += 1

    def extend(self, values):
        for value in values:
            self.append(value)

    def remove(self, value):
        for index, item in enumerate(self):
            if item == value:
                del self[index]
                return
        raise ValueError(f"{value} not in list")

    def pop(self, index=-1):
        if self.length == 0:
            raise IndexError("pop from empty list")
        if index < 0:
            index += self.length
        value = self[index]
        del self[index]
        return value

    def clear(self):
        self.cache.clear()
        self.file_paths = []
        self.length = 0

    def index(self, value, start=0, stop=None):
        if stop is None:
            stop = self.length
        for i in range(start, stop):
            if self[i] == value:
                return i
        raise ValueError(f"{value} is not in list")
    
    def get(self, index, default=None):
        try:
            return self[index]
        except IndexError:
            return default

    def cleanup(self):
        for file_path in self.file_paths:
            if os.path.exists(file_path):
                os.remove(file_path)
        if os.path.exists(self.temp_dir):
            os.rmdir(self.temp_dir)

    def __del__(self):
        self.cleanup()


class PaginatedDict:
    instance_counter = 0

    def __init__(self, page_size=1):
        self.page_size = page_size
        self.file_paths = []
        self.cache = {}
        self.key_to_page = {}
        self.length = 0  # Track the number of items
        self.instance_id = PaginatedDict.instance_counter
        PaginatedDict.instance_counter += 1
        self.temp_dir = tempfile.mkdtemp(prefix=f'paginated_dict_{self.instance_id}_', dir='/Users/snaow/repos/prowler')
        print(f"Temporary directory for instance {self.instance_id}: {self.temp_dir}")
        atexit.register(self.cleanup)
        
    def _save_page(self, page_data, page_num):
        file_path = os.path.join(self.temp_dir, f'page_{page_num}.pkl')
        with open(file_path, 'wb') as f:
            pickle.dump(page_data, f)
        if page_num >= len(self.file_paths):
            self.file_paths.append(file_path)
        else:
            self.file_paths[page_num] = file_path
    
    def _load_page(self, page_num):
        if page_num in self.cache:
            return self.cache[page_num]
        with open(self.file_paths[page_num], 'rb') as f:
            page_data = pickle.load(f)
        self.cache[page_num] = page_data
        return page_data

    def __setitem__(self, key, value):
        if key in self.key_to_page:
            page_num = self.key_to_page[key]
            page_data = self._load_page(page_num)
            page_data[key] = value
        else:
            page_num = self.length // self.page_size
            if page_num >= len(self.file_paths):
                self._save_page({}, page_num)
            page_data = self._load_page(page_num)
            page_data[key] = value
            self.key_to_page[key] = page_num
            self.length += 1
        self.cache[page_num] = page_data
        self._save_page(page_data, page_num)

    def __getitem__(self, key):
        if key not in self.key_to_page:
            raise KeyError(f"Key {key} not found")
        page_num = self.key_to_page[key]
        page_data = self._load_page(page_num)
        return page_data[key]

    def __delitem__(self, key):
        if key not in self.key_to_page:
            raise KeyError(f"Key {key} not found")
        page_num = self.key_to_page[key]
        page_data = self._load_page(page_num)
        del page_data[key]
        del self.key_to_page[key]
        self.cache[page_num] = page_data
        self._save_page(page_data, page_num)
        self.length -= 1

    def __len__(self):
        return self.length

    def __iter__(self):
        for page_num in range(len(self.file_paths)):
            page_data = self._load_page(page_num)
            for key in page_data:
                yield key

    def get(self, key, default=None):
        try:
            return self[key]
        except KeyError:
            return default

    def keys(self):
        for key in self:
            yield key

    def values(self):
        for key in self:
            yield self[key]

    def items(self):
        for key in self:
            yield (key, self[key])

    def clear(self):
        self.cache.clear()
        self.key_to_page.clear()
        self.file_paths = []
        self.length = 0

    def cleanup(self):
        for file_path in self.file_paths:
            if os.path.exists(file_path):
                os.remove(file_path)
        if os.path.exists(self.temp_dir):
            os.rmdir(self.temp_dir)

    def __del__(self):
        self.cleanup()

################## EC2

class EC2(AWSService):
    
    def __init__(self, provider):
        # Call AWSService's __init__
        memory_usage = check_memory_usage()
        print(f"Memory usage at __init__ ec2_service.py : {memory_usage / (1024 * 1024)} MB")
        #pdb.set_trace()  # Break
        super().__init__(__class__.__name__, provider)
        self.account_arn_template = f"arn:{self.audited_partition}:ec2:{self.region}:{self.audited_account}:account"
        paginated = 1
        memory_usage = check_memory_usage()
        print(f"Memory usage at super() ec2_service.py : {memory_usage / (1024 * 1024)} MB")
        #pdb.set_trace()  # Break
        if paginated:
            self.instances = PaginatedList()
            self.security_groups = PaginatedList()
            self.regions_with_sgs = PaginatedList()
            self.volumes_with_snapshots = PaginatedDict()
            self.regions_with_snapshots = PaginatedDict()
            self.network_acls = PaginatedList()
            self.snapshots = PaginatedList()
            self.network_interfaces = PaginatedList()
            self.images = PaginatedList()
            self.volumes = PaginatedList()
            self.attributes_for_regions = PaginatedDict()
            self.ebs_encryption_by_default = PaginatedList()
            self.elastic_ips = PaginatedList()
            self.ebs_block_public_access_snapshots_states = PaginatedList()
            self.instance_metadata_defaults = PaginatedList()
            self.launch_templates = PaginatedList()
        else:
            self.instances = []
            self.security_groups = []
            self.regions_with_sgs = []
            self.volumes_with_snapshots = {}
            self.regions_with_snapshots = {}
            self.network_acls = []
            self.snapshots = []
            self.network_interfaces = []
            self.images = []
            self.volumes = []
            self.attributes_for_regions = {}
            self.ebs_encryption_by_default = []
            self.elastic_ips = []
            self.ebs_block_public_access_snapshots_states = []
            self.instance_metadata_defaults = []
            self.launch_templates = []

        
        self.__threading_call__(self.__describe_instances__)
        #self.__describe_instances__(next(iter(self.regional_clients.values())))
        self.__threading_call__(self.__get_instance_user_data__, self.instances)
        self.__threading_call__(self.__describe_security_groups__)
        self.__threading_call__(self.__describe_network_acls__)
        self.__threading_call__(self.__describe_snapshots__)
        self.__threading_call__(self.__determine_public_snapshots__, self.snapshots)
        self.__threading_call__(self.__describe_network_interfaces__)
        self.__threading_call__(self.__describe_images__)
        self.__threading_call__(self.__describe_volumes__)
        self.__threading_call__(self.__get_resources_for_regions__)
        self.__threading_call__(self.__get_ebs_encryption_settings__)
        self.__threading_call__(self.__describe_ec2_addresses__)
        self.__threading_call__(self.__get_snapshot_block_public_access_state__)
        self.__threading_call__(self.__get_instance_metadata_defaults__)
        self.__threading_call__(self.__describe_launch_templates)
        self.__threading_call__(
            self.__get_launch_template_versions__, self.launch_templates
        )

        print("MY DICT---<>")
        print(list(self.instances))
    def cleanup(self):
        del self.instances
        del self.security_groups
        del self.regions_with_sgs
        del self.volumes_with_snapshots
        del self.regions_with_snapshots
        del self.network_acls
        del self.snapshots
        del self.network_interfaces
        del self.images
        del self.volumes
        del self.attributes_for_regions
        del self.ebs_encryption_by_default
        del self.elastic_ips
        del self.ebs_block_public_access_snapshots_states
        del self.instance_metadata_defaults
        del self.launch_templates
        gc.collect()

    def __get_volume_arn_template__(self, region):
        return (
            f"arn:{self.audited_partition}:ec2:{region}:{self.audited_account}:volume"
        )
    
    #@mock_aws
    def __describe_instances__(self, regional_client):
        try:
            mock_enabled = 0
            if mock_enabled:
                ec2 = boto3.resource('ec2', region_name='eu-west-1')
                instances = []
                counter = 0
                
                instance = ec2.create_instances(
                    ImageId='ami-12345678',  # Example AMI ID, replace with a valid one if testing with real AWS
                    MinCount=3000,
                    MaxCount=3000,
                    InstanceType='t2.micro'
                )[0]
                instance.wait_until_running()
                instance.reload()
            
            describe_instances_paginator = regional_client.get_paginator(
                "describe_instances"
            )

            memory_usage = check_memory_usage()
            print(f"Memory usage at regional_client.get_paginator ({regional_client.region}) : {memory_usage / (1024 * 1024)} MB")
            #pdb.set_trace()  # Break
            describe_instances_paginator_iterator = describe_instances_paginator.paginate(PaginationConfig={'MaxItems': 1})
            #describe_instances_paginator_iterator = describe_instances_paginator.paginate()
            memory_usage = check_memory_usage()
            print(f"Memory usage at describe_instances_paginator.paginate() ({regional_client.region}) : {memory_usage / (1024 * 1024)} MB")
            
            for page in describe_instances_paginator_iterator:
                size_bytes = asizeof.asizeof(page)
                size_mb = size_bytes / (1024 * 1024)
                print("\tMemory usage of page", size_mb, "MB")
            #for page in describe_instances_paginator.paginate():
                memory_usage = check_memory_usage()
                print(f"\tMemory usage at describe_instances_paginator.paginate() start : {memory_usage / (1024 * 1024)} MB")
                #pdb.set_trace()  # Break
                for reservation in page["Reservations"]:
                    for instance in reservation["Instances"]:
                        arn = f"arn:{self.audited_partition}:ec2:{regional_client.region}:{self.audited_account}:instance/{instance['InstanceId']}"
                        #print(arn)
                        if not self.audit_resources or (
                            is_resource_filtered(arn, self.audit_resources)
                        ):
                            self.instances.append(
                                Instance(
                                    id=instance["InstanceId"],
                                    arn=arn,
                                    state=instance["State"]["Name"],
                                    region=regional_client.region,
                                    type=instance["InstanceType"],
                                    image_id=instance["ImageId"],
                                    launch_time=instance["LaunchTime"],
                                    private_dns=instance["PrivateDnsName"],
                                    private_ip=instance.get("PrivateIpAddress"),
                                    public_dns=instance.get("PublicDnsName"),
                                    public_ip=instance.get("PublicIpAddress"),
                                    http_tokens=instance.get("MetadataOptions", {}).get(
                                        "HttpTokens"
                                    ),
                                    http_endpoint=instance.get(
                                        "MetadataOptions", {}
                                    ).get("HttpEndpoint"),
                                    instance_profile=instance.get("IamInstanceProfile"),
                                    monitoring_state=instance.get(
                                        "Monitoring", {"State": "disabled"}
                                    ).get("State", "disabled"),
                                    security_groups=[
                                        sg["GroupId"]
                                        for sg in instance.get("SecurityGroups", [])
                                    ],
                                    subnet_id=instance.get("SubnetId", ""),
                                    tags=instance.get("Tags"),
                                )
                            )
                            memory_usage = check_memory_usage()
                            print(f"\t\tMemory usage at self.instances.append : {memory_usage / (1024 * 1024)} MB")
                            #pdb.set_trace()  # Break
                memory_usage = check_memory_usage()
                print(f"\tMemory usage at describe_instances_paginator.paginate() end : {memory_usage / (1024 * 1024)} MB")
                #pdb.set_trace()  # Break
            memory_usage = check_memory_usage()
            print(f"Memory usage at the end of describe_instances_paginator ({regional_client.region}): {memory_usage / (1024 * 1024)} MB")
            
                            

        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __describe_security_groups__(self, regional_client):
        try:
            describe_security_groups_paginator = regional_client.get_paginator(
                "describe_security_groups"
            )
            describe_security_groups_iterator = describe_security_groups_paginator.paginate(PaginationConfig={'MaxItems': 1})
            for page in describe_security_groups_iterator:
                for sg in page["SecurityGroups"]:
                    arn = f"arn:{self.audited_partition}:ec2:{regional_client.region}:{self.audited_account}:security-group/{sg['GroupId']}"
                    if not self.audit_resources or (
                        is_resource_filtered(arn, self.audit_resources)
                    ):
                        associated_sgs = []
                        for ingress_rule in sg["IpPermissions"]:
                            # check associated security groups
                            for sg_group in ingress_rule.get("UserIdGroupPairs", []):
                                if sg_group.get("GroupId"):
                                    associated_sgs.append(sg_group["GroupId"])
                        self.security_groups.append(
                            SecurityGroup(
                                name=sg["GroupName"],
                                arn=arn,
                                region=regional_client.region,
                                id=sg["GroupId"],
                                ingress_rules=sg["IpPermissions"],
                                egress_rules=sg["IpPermissionsEgress"],
                                associated_sgs=associated_sgs,
                                vpc_id=sg["VpcId"],
                                tags=sg.get("Tags"),
                            )
                        )
                        if sg["GroupName"] != "default":
                            self.regions_with_sgs.append(regional_client.region)
            memory_usage = check_memory_usage()
            print(f"Memory usage after __describe_security_groups__: {memory_usage / (1024 * 1024)} MB")
            #pdb.set_trace()  # Break
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __describe_network_acls__(self, regional_client):
        try:
            describe_network_acls_paginator = regional_client.get_paginator(
                "describe_network_acls"
            )
            for page in describe_network_acls_paginator.paginate(PaginationConfig={'MaxItems': 1}):
                for nacl in page["NetworkAcls"]:
                    arn = f"arn:{self.audited_partition}:ec2:{regional_client.region}:{self.audited_account}:network-acl/{nacl['NetworkAclId']}"
                    if not self.audit_resources or (
                        is_resource_filtered(arn, self.audit_resources)
                    ):
                        nacl_name = ""
                        for tag in nacl.get("Tags", []):
                            if tag["Key"] == "Name":
                                nacl_name = tag["Value"]
                        self.network_acls.append(
                            NetworkACL(
                                id=nacl["NetworkAclId"],
                                arn=arn,
                                name=nacl_name,
                                region=regional_client.region,
                                entries=nacl["Entries"],
                                tags=nacl.get("Tags"),
                            )
                        )
            memory_usage = check_memory_usage()
            print(f"Memory usage after __describe_network_acls__: {memory_usage / (1024 * 1024)} MB")
            #pdb.set_trace()  # Break
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __describe_snapshots__(self, regional_client):
        try:
            snapshots_in_region = False
            describe_snapshots_paginator = regional_client.get_paginator(
                "describe_snapshots"
            )
            for page in describe_snapshots_paginator.paginate(OwnerIds=["self"]):
                for snapshot in page["Snapshots"]:
                    arn = f"arn:{self.audited_partition}:ec2:{regional_client.region}:{self.audited_account}:snapshot/{snapshot['SnapshotId']}"
                    if not self.audit_resources or (
                        is_resource_filtered(arn, self.audit_resources)
                    ):
                        if snapshots_in_region is False:
                            snapshots_in_region = True
                        self.snapshots.append(
                            Snapshot(
                                id=snapshot["SnapshotId"],
                                arn=arn,
                                region=regional_client.region,
                                encrypted=snapshot.get("Encrypted", False),
                                tags=snapshot.get("Tags"),
                                volume=snapshot["VolumeId"],
                            )
                        )
                        # Store that the volume has at least one snapshot
                        self.volumes_with_snapshots[snapshot["VolumeId"]] = True
            # Store that the region has at least one snapshot
            self.regions_with_snapshots[regional_client.region] = snapshots_in_region
            memory_usage = check_memory_usage()
            print(f"Memory usage after describe_snapshots: {memory_usage / (1024 * 1024)} MB")
            #pdb.set_trace()  # Break
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __determine_public_snapshots__(self, snapshot):
        try:
            regional_client = self.regional_clients[snapshot.region]
            snapshot_public = regional_client.describe_snapshot_attribute(
                Attribute="createVolumePermission", SnapshotId=snapshot.id
            )
            for permission in snapshot_public["CreateVolumePermissions"]:
                if "Group" in permission:
                    if permission["Group"] == "all":
                        snapshot.public = True

        except ClientError as error:
            if error.response["Error"]["Code"] == "InvalidSnapshot.NotFound":
                logger.warning(
                    f"{snapshot.region} --"
                    f" {error.__class__.__name__}[{error.__traceback__.tb_lineno}]:"
                    f" {error}"
                )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __describe_network_interfaces__(self, regional_client):
        try:
            # Get Network Interfaces with Public IPs
            describe_network_interfaces_paginator = regional_client.get_paginator(
                "describe_network_interfaces"
            )
            for page in describe_network_interfaces_paginator.paginate():
                for interface in page["NetworkInterfaces"]:
                    eni = NetworkInterface(
                        id=interface["NetworkInterfaceId"],
                        association=interface.get("Association", {}),
                        attachment=interface.get("Attachment", {}),
                        private_ip=interface.get("PrivateIpAddress"),
                        type=interface["InterfaceType"],
                        subnet_id=interface["SubnetId"],
                        vpc_id=interface["VpcId"],
                        region=regional_client.region,
                        tags=interface.get("TagSet"),
                    )
                    self.network_interfaces.append(eni)
                    # Add Network Interface to Security Group
                    # 'Groups': [
                    #     {
                    #         'GroupId': 'sg-xxxxx',
                    #         'GroupName': 'default',
                    #     },
                    # ],
                    self.__add_network_interfaces_to_security_groups__(
                        eni, interface.get("Groups", [])
                    )
            memory_usage = check_memory_usage()
            print(f"Memory usage after network_interfaces: {memory_usage / (1024 * 1024)} MB")
            #pdb.set_trace()  # Break

        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __add_network_interfaces_to_security_groups__(
        self, interface, interface_security_groups
    ):
        try:
            for sg in interface_security_groups:
                for security_group in self.security_groups:
                    if security_group.id == sg["GroupId"]:
                        security_group.network_interfaces.append(interface)
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __get_instance_user_data__(self, instance):
        try:
            regional_client = self.regional_clients[instance.region]
            user_data = regional_client.describe_instance_attribute(
                Attribute="userData", InstanceId=instance.id
            )["UserData"]
            if "Value" in user_data:
                instance.user_data = user_data["Value"]
            memory_usage = check_memory_usage()
            print(f"Memory usage after __get_instance_user_data__: {memory_usage / (1024 * 1024)} MB")
            #pdb.set_trace()  # Break
        except ClientError as error:
            if error.response["Error"]["Code"] == "InvalidInstanceID.NotFound":
                logger.warning(
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __describe_images__(self, regional_client):
        try:
            for image in regional_client.describe_images(Owners=["self"])["Images"]:
                arn = f"arn:{self.audited_partition}:ec2:{regional_client.region}:{self.audited_account}:image/{image['ImageId']}"
                if not self.audit_resources or (
                    is_resource_filtered(arn, self.audit_resources)
                ):
                    self.images.append(
                        Image(
                            id=image["ImageId"],
                            arn=arn,
                            name=image["Name"],
                            public=image.get("Public", False),
                            region=regional_client.region,
                            tags=image.get("Tags"),
                        )
                    )
            memory_usage = check_memory_usage()
            print(f"Memory usage after __describe_images__: {memory_usage / (1024 * 1024)} MB")
            #pdb.set_trace()  # Break
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __describe_volumes__(self, regional_client):
        try:
            describe_volumes_paginator = regional_client.get_paginator(
                "describe_volumes"
            )
            for page in describe_volumes_paginator.paginate():
                for volume in page["Volumes"]:
                    arn = f"arn:{self.audited_partition}:ec2:{regional_client.region}:{self.audited_account}:volume/{volume['VolumeId']}"
                    if not self.audit_resources or (
                        is_resource_filtered(arn, self.audit_resources)
                    ):
                        self.volumes.append(
                            Volume(
                                id=volume["VolumeId"],
                                arn=arn,
                                region=regional_client.region,
                                encrypted=volume["Encrypted"],
                                tags=volume.get("Tags"),
                            )
                        )
            memory_usage = check_memory_usage()
            print(f"Memory usage after __describe_volumes__: {memory_usage / (1024 * 1024)} MB")
            #pdb.set_trace()  # Break
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __describe_ec2_addresses__(self, regional_client):
        try:
            for address in regional_client.describe_addresses()["Addresses"]:
                public_ip = None
                association_id = None
                allocation_id = None
                if "PublicIp" in address:
                    public_ip = address["PublicIp"]
                if "AssociationId" in address:
                    association_id = address["AssociationId"]
                if "AllocationId" in address:
                    allocation_id = address["AllocationId"]
                elastic_ip_arn = f"arn:{self.audited_partition}:ec2:{regional_client.region}:{self.audited_account}:eip-allocation/{allocation_id}"
                if not self.audit_resources or (
                    is_resource_filtered(elastic_ip_arn, self.audit_resources)
                ):
                    self.elastic_ips.append(
                        ElasticIP(
                            public_ip=public_ip,
                            association_id=association_id,
                            allocation_id=allocation_id,
                            arn=elastic_ip_arn,
                            region=regional_client.region,
                            tags=address.get("Tags"),
                        )
                    )
            memory_usage = check_memory_usage()
            print(f"Memory usage after __describe_ec2_addresses__: {memory_usage / (1024 * 1024)} MB")
            #pdb.set_trace()  # Break
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __get_ebs_encryption_settings__(self, regional_client):
        try:
            volumes_in_region = self.attributes_for_regions.get(
                regional_client.region, []
            )
            volumes_in_region = volumes_in_region.get("has_volumes", False)
            self.ebs_encryption_by_default.append(
                EbsEncryptionByDefault(
                    status=regional_client.get_ebs_encryption_by_default()[
                        "EbsEncryptionByDefault"
                    ],
                    volumes=volumes_in_region,
                    region=regional_client.region,
                )
            )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __get_snapshot_block_public_access_state__(self, regional_client):
        try:
            snapshots_in_region = self.attributes_for_regions.get(
                regional_client.region, []
            )
            snapshots_in_region = snapshots_in_region.get("has_snapshots", False)
            self.ebs_block_public_access_snapshots_states.append(
                EbsSnapshotBlockPublicAccess(
                    status=regional_client.get_snapshot_block_public_access_state()[
                        "State"
                    ],
                    snapshots=snapshots_in_region,
                    region=regional_client.region,
                )
            )
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __get_instance_metadata_defaults__(self, regional_client):
        try:
            instances_in_region = self.attributes_for_regions.get(
                regional_client.region, []
            )
            instances_in_region = instances_in_region.get("has_instances", False)
            metadata_defaults = regional_client.get_instance_metadata_defaults()
            account_level = metadata_defaults.get("AccountLevel", {})
            self.instance_metadata_defaults.append(
                InstanceMetadataDefaults(
                    http_tokens=account_level.get("HttpTokens", None),
                    instances=instances_in_region,
                    region=regional_client.region,
                )
            )
            memory_usage = check_memory_usage()
            print(f"Memory usage after __get_instance_metadata_defaults__: {memory_usage / (1024 * 1024)} MB")
            #pdb.set_trace()  # Break
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __get_resources_for_regions__(self, regional_client):
        try:
            has_instances = False
            for instance in self.instances:
                if instance.region == regional_client.region:
                    has_instances = True
                    break
            has_snapshots = False
            for snapshot in self.snapshots:
                if snapshot.region == regional_client.region:
                    has_snapshots = True
                    break
            has_volumes = False
            for volume in self.volumes:
                if volume.region == regional_client.region:
                    has_volumes = True
                    break
            self.attributes_for_regions[regional_client.region] = {
                "has_instances": has_instances,
                "has_snapshots": has_snapshots,
                "has_volumes": has_volumes,
            }
            memory_usage = check_memory_usage()
            print(f"Memory usage after __get_resources_for_regions__: {memory_usage / (1024 * 1024)} MB")
            #pdb.set_trace()  # Break
        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __describe_launch_templates(self, regional_client):
        try:
            describe_launch_templates_paginator = regional_client.get_paginator(
                "describe_launch_templates"
            )

            for page in describe_launch_templates_paginator.paginate():
                for template in page["LaunchTemplates"]:
                    template_arn = f"arn:aws:ec2:{regional_client.region}:{self.audited_account}:launch-template/{template['LaunchTemplateId']}"
                    if not self.audit_resources or (
                        is_resource_filtered(template_arn, self.audit_resources)
                    ):
                        self.launch_templates.append(
                            LaunchTemplate(
                                name=template["LaunchTemplateName"],
                                id=template["LaunchTemplateId"],
                                arn=template_arn,
                                region=regional_client.region,
                                versions=[],
                            )
                        )

        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def __get_launch_template_versions__(self, launch_template):
        try:
            regional_client = self.regional_clients[launch_template.region]
            describe_launch_template_versions_paginator = regional_client.get_paginator(
                "describe_launch_template_versions"
            )

            for page in describe_launch_template_versions_paginator.paginate(
                LaunchTemplateId=launch_template.id
            ):
                for template_version in page["LaunchTemplateVersions"]:
                    launch_template.versions.append(
                        LaunchTemplateVersion(
                            version_number=template_version["VersionNumber"],
                            template_data=template_version["LaunchTemplateData"],
                        )
                    )

        except Exception as error:
            logger.error(
                f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class Instance(BaseModel):
    id: str
    arn: str
    state: str
    region: str
    type: str
    image_id: str
    launch_time: datetime
    private_dns: str
    private_ip: Optional[str]
    public_dns: Optional[str]
    public_ip: Optional[str]
    user_data: Optional[str]
    http_tokens: Optional[str]
    http_endpoint: Optional[str]
    monitoring_state: str
    security_groups: list[str]
    subnet_id: str
    instance_profile: Optional[dict]
    tags: Optional[list] = []


class Snapshot(BaseModel):
    id: str
    arn: str
    region: str
    encrypted: bool
    public: bool = False
    tags: Optional[list] = []
    volume: Optional[str]


class Volume(BaseModel):
    id: str
    arn: str
    region: str
    encrypted: bool
    tags: Optional[list] = []


class NetworkInterface(BaseModel):
    id: str
    association: dict
    attachment: dict
    private_ip: Optional[str]
    type: str
    subnet_id: str
    vpc_id: str
    region: str
    tags: Optional[list] = []


class SecurityGroup(BaseModel):
    name: str
    arn: str
    region: str
    id: str
    vpc_id: str
    associated_sgs: list
    network_interfaces: list[NetworkInterface] = []
    ingress_rules: list[dict]
    egress_rules: list[dict]
    tags: Optional[list] = []


class NetworkACL(BaseModel):
    id: str
    arn: str
    name: str
    region: str
    entries: list[dict]
    tags: Optional[list] = []


class ElasticIP(BaseModel):
    public_ip: Optional[str]
    association_id: Optional[str]
    arn: str
    allocation_id: Optional[str]
    region: str
    tags: Optional[list] = []


class Image(BaseModel):
    id: str
    arn: str
    name: str
    public: bool
    region: str
    tags: Optional[list] = []


class EbsEncryptionByDefault(BaseModel):
    status: bool
    volumes: bool
    region: str


class EbsSnapshotBlockPublicAccess(BaseModel):
    status: str
    snapshots: bool
    region: str


class InstanceMetadataDefaults(BaseModel):
    http_tokens: Optional[str]
    instances: bool
    region: str


class LaunchTemplateVersion(BaseModel):
    version_number: int
    template_data: dict


class LaunchTemplate(BaseModel):
    name: str
    id: str
    arn: str
    region: str
    versions: list[LaunchTemplateVersion] = []
