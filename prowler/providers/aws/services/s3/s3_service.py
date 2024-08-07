import json
from typing import Optional

from botocore.client import ClientError
from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.lib.scan_filters.scan_filters import is_resource_filtered
from prowler.providers.aws.lib.service.service import AWSService
import os 
import dill as pickle
import os
import atexit
from collections import deque
from sys import getsizeof
import tempfile


class PaginatedList:
    instance_counter = 0

    def __init__(self, page_size=10):
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
        if hasattr(self, 'file_paths'):
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

################## S3
class S3(AWSService):
    def __init__(self, provider):
        # Call AWSService's __init__
        super().__init__(__class__.__name__, provider)
        self.account_arn_template = f"arn:{self.audited_partition}:s3:{self.region}:{self.audited_account}:account"
        self.regions_with_buckets = []
        self.buckets = self.__list_buckets__(provider)
        self.__threading_call__(self.__get_bucket_versioning__, self.buckets)
        self.__threading_call__(self.__get_bucket_logging__, self.buckets)
        self.__threading_call__(self.__get_bucket_policy__, self.buckets)
        self.__threading_call__(self.__get_bucket_acl__, self.buckets)
        self.__threading_call__(self.__get_public_access_block__, self.buckets)
        self.__threading_call__(self.__get_bucket_encryption__, self.buckets)
        self.__threading_call__(self.__get_bucket_ownership_controls__, self.buckets)
        self.__threading_call__(self.__get_object_lock_configuration__, self.buckets)
        self.__threading_call__(self.__get_bucket_tagging__, self.buckets)

    def cleanup(self):
        del self.regions_with_buckets
        del self.buckets

    def __list_buckets__(self, provider):
        logger.info("S3 - Listing buckets...")
        buckets = PaginatedList()
        try:
            list_buckets = self.client.list_buckets()
            for bucket in list_buckets["Buckets"]:
                try:
                    bucket_region = self.client.get_bucket_location(
                        Bucket=bucket["Name"]
                    )["LocationConstraint"]
                    if bucket_region == "EU":  # If EU, bucket_region is eu-west-1
                        bucket_region = "eu-west-1"
                    if not bucket_region:  # If None, bucket_region is us-east-1
                        bucket_region = "us-east-1"
                    # Arn
                    arn = f"arn:{self.audited_partition}:s3:::{bucket['Name']}"
                    if not self.audit_resources or (
                        is_resource_filtered(arn, self.audit_resources)
                    ):
                        self.regions_with_buckets.append(bucket_region)
                        # Check if there are filter regions
                        if provider.identity.audited_regions:
                            # FIXME: what if the bucket comes from a CloudTrail bucket in another audited region
                            if bucket_region in provider.identity.audited_regions:
                                buckets.append(
                                    Bucket(
                                        name=bucket["Name"],
                                        arn=arn,
                                        region=bucket_region,
                                    )
                                )
                        else:
                            buckets.append(
                                Bucket(
                                    name=bucket["Name"], arn=arn, region=bucket_region
                                )
                            )
                except ClientError as error:
                    if error.response["Error"]["Code"] == "NoSuchBucket":
                        logger.warning(
                            f"{bucket['Name']} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                        )
                    else:
                        logger.error(
                            f"{bucket['Name']} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                        )
                except Exception as error:
                    logger.error(
                        f"{bucket['Name']} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                    )
        except ClientError as error:
            if error.response["Error"]["Code"] == "NotSignedUp":
                logger.warning(
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
            else:
                logger.error(
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        return buckets

    def __get_bucket_versioning__(self, bucket):
        logger.info("S3 - Get buckets versioning...")
        try:
            regional_client = self.regional_clients[bucket.region]
            bucket_versioning = regional_client.get_bucket_versioning(
                Bucket=bucket.name
            )
            if "Status" in bucket_versioning:
                if "Enabled" == bucket_versioning["Status"]:
                    bucket.versioning = True
            if "MFADelete" in bucket_versioning:
                if "Enabled" == bucket_versioning["MFADelete"]:
                    bucket.mfa_delete = True
        except ClientError as error:
            if error.response["Error"]["Code"] == "NoSuchBucket":
                logger.warning(
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
            else:
                logger.error(
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
        except Exception as error:
            if bucket.region:
                logger.error(
                    f"{bucket.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
            else:
                logger.error(
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )

    def __get_bucket_encryption__(self, bucket):
        logger.info("S3 - Get buckets encryption...")
        try:
            regional_client = self.regional_clients[bucket.region]
            bucket.encryption = regional_client.get_bucket_encryption(
                Bucket=bucket.name
            )["ServerSideEncryptionConfiguration"]["Rules"][0][
                "ApplyServerSideEncryptionByDefault"
            ][
                "SSEAlgorithm"
            ]
        except ClientError as error:
            if error.response["Error"]["Code"] == "NoSuchBucket":
                logger.warning(
                    f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
            else:
                logger.error(
                    f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
        except Exception as error:
            if "ServerSideEncryptionConfigurationNotFoundError" in str(error):
                bucket.encryption = None
            elif regional_client:
                logger.error(
                    f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
            else:
                logger.error(
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )

    def __get_bucket_logging__(self, bucket):
        logger.info("S3 - Get buckets logging...")
        try:
            regional_client = self.regional_clients[bucket.region]
            bucket_logging = regional_client.get_bucket_logging(Bucket=bucket.name)
            if "LoggingEnabled" in bucket_logging:
                bucket.logging = True
                bucket.logging_target_bucket = bucket_logging["LoggingEnabled"][
                    "TargetBucket"
                ]
        except ClientError as error:
            if error.response["Error"]["Code"] == "NoSuchBucket":
                logger.warning(
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
            else:
                logger.error(
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
        except Exception as error:
            if regional_client:
                logger.error(
                    f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
            else:
                logger.error(
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )

    def __get_public_access_block__(self, bucket):
        logger.info("S3 - Get buckets public access block...")
        try:
            regional_client = self.regional_clients[bucket.region]
            public_access_block = regional_client.get_public_access_block(
                Bucket=bucket.name
            )["PublicAccessBlockConfiguration"]
            bucket.public_access_block = PublicAccessBlock(
                block_public_acls=public_access_block["BlockPublicAcls"],
                ignore_public_acls=public_access_block["IgnorePublicAcls"],
                block_public_policy=public_access_block["BlockPublicPolicy"],
                restrict_public_buckets=public_access_block["RestrictPublicBuckets"],
            )
        except ClientError as error:
            if error.response["Error"]["Code"] == "NoSuchBucket":
                logger.warning(
                    f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
            elif (
                error.response["Error"]["Code"]
                == "NoSuchPublicAccessBlockConfiguration"
            ):
                # Set all block as False
                bucket.public_access_block = PublicAccessBlock(
                    block_public_acls=False,
                    ignore_public_acls=False,
                    block_public_policy=False,
                    restrict_public_buckets=False,
                )
            else:
                logger.error(
                    f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
        except Exception as error:
            if regional_client:
                logger.error(
                    f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
            else:
                logger.error(
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )

    def __get_bucket_acl__(self, bucket):
        logger.info("S3 - Get buckets acl...")
        try:
            regional_client = self.regional_clients[bucket.region]
            grantees = []
            acl_grants = regional_client.get_bucket_acl(Bucket=bucket.name)["Grants"]
            for grant in acl_grants:
                grantee = ACL_Grantee(type=grant["Grantee"]["Type"])
                if "DisplayName" in grant["Grantee"]:
                    grantee.display_name = grant["Grantee"]["DisplayName"]
                if "ID" in grant["Grantee"]:
                    grantee.ID = grant["Grantee"]["ID"]
                if "URI" in grant["Grantee"]:
                    grantee.URI = grant["Grantee"]["URI"]
                if "Permission" in grant:
                    grantee.permission = grant["Permission"]
                grantees.append(grantee)
            bucket.acl_grantees = grantees
        except ClientError as error:
            if error.response["Error"]["Code"] == "NoSuchBucket":
                logger.warning(
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
            else:
                logger.error(
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
        except Exception as error:
            if regional_client:
                logger.error(
                    f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
            else:
                logger.error(
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )

    def __get_bucket_policy__(self, bucket):
        logger.info("S3 - Get buckets policy...")
        try:
            regional_client = self.regional_clients[bucket.region]
            bucket.policy = json.loads(
                regional_client.get_bucket_policy(Bucket=bucket.name)["Policy"]
            )
        except ClientError as error:
            if error.response["Error"]["Code"] == "NoSuchBucketPolicy":
                bucket.policy = {}
            elif error.response["Error"]["Code"] == "NoSuchBucket":
                logger.warning(
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
            else:
                logger.error(
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
        except Exception as error:
            if regional_client:
                logger.error(
                    f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
            else:
                logger.error(
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )

    def __get_bucket_ownership_controls__(self, bucket):
        logger.info("S3 - Get buckets ownership controls...")
        try:
            regional_client = self.regional_clients[bucket.region]
            bucket.ownership = regional_client.get_bucket_ownership_controls(
                Bucket=bucket.name
            )["OwnershipControls"]["Rules"][0]["ObjectOwnership"]
        except ClientError as error:
            if error.response["Error"]["Code"] == "NoSuchBucket":
                logger.warning(
                    f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
            elif error.response["Error"]["Code"] == "OwnershipControlsNotFoundError":
                bucket.ownership = None
            else:
                logger.error(
                    f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
        except Exception as error:
            if regional_client:
                logger.error(
                    f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
            else:
                logger.error(
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )

    def __get_object_lock_configuration__(self, bucket):
        logger.info("S3 - Get buckets ownership controls...")
        try:
            regional_client = self.regional_clients[bucket.region]
            regional_client.get_object_lock_configuration(Bucket=bucket.name)
            bucket.object_lock = True
        except Exception as error:
            if (
                "ObjectLockConfigurationNotFoundError" in str(error)
                or error.response["Error"]["Code"] == "NoSuchBucket"
            ):
                bucket.object_lock = False
                if regional_client:
                    logger.warning(
                        f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                    )
                else:
                    logger.warning(
                        f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                    )
            else:
                if regional_client:
                    logger.error(
                        f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                    )
                else:
                    logger.error(
                        f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                    )

    def __get_bucket_tagging__(self, bucket):
        logger.info("S3 - Get buckets logging...")
        try:
            regional_client = self.regional_clients[bucket.region]
            bucket_tags = regional_client.get_bucket_tagging(Bucket=bucket.name)[
                "TagSet"
            ]
            bucket.tags = bucket_tags
        except ClientError as error:
            bucket.tags = []
            if error.response["Error"]["Code"] != "NoSuchTagSet":
                if error.response["Error"]["Code"] == "NoSuchBucket":
                    logger.warning(
                        f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                    )
                else:
                    logger.error(
                        f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                    )
        except Exception as error:
            if regional_client:
                logger.error(
                    f"{regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
            else:
                logger.error(
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )


################## S3Control
class S3Control(AWSService):
    def __init__(self, provider):
        # Call AWSService's __init__
        super().__init__(__class__.__name__, provider, global_service=True)
        self.account_public_access_block = self.__get_public_access_block__()

    def __get_public_access_block__(self):
        logger.info("S3 - Get account public access block...")
        try:
            public_access_block = self.client.get_public_access_block(
                AccountId=self.audited_account
            )["PublicAccessBlockConfiguration"]
            return PublicAccessBlock(
                block_public_acls=public_access_block["BlockPublicAcls"],
                ignore_public_acls=public_access_block["IgnorePublicAcls"],
                block_public_policy=public_access_block["BlockPublicPolicy"],
                restrict_public_buckets=public_access_block["RestrictPublicBuckets"],
            )
        except Exception as error:
            if "NoSuchPublicAccessBlockConfiguration" in str(error):
                # Set all block as False
                return PublicAccessBlock(
                    block_public_acls=False,
                    ignore_public_acls=False,
                    block_public_policy=False,
                    restrict_public_buckets=False,
                )
            logger.error(
                f"{self.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class ACL_Grantee(BaseModel):
    display_name: Optional[str]
    ID: Optional[str]
    type: str
    URI: Optional[str]
    permission: Optional[str]


class PublicAccessBlock(BaseModel):
    block_public_acls: bool
    ignore_public_acls: bool
    block_public_policy: bool
    restrict_public_buckets: bool


class Bucket(BaseModel):
    name: str
    arn: str
    versioning: bool = False
    logging: bool = False
    public_access_block: Optional[PublicAccessBlock]
    acl_grantees: list[ACL_Grantee] = []
    policy: dict = {}
    encryption: Optional[str]
    region: str
    logging_target_bucket: Optional[str]
    ownership: Optional[str]
    object_lock: bool = False
    mfa_delete: bool = False
    tags: Optional[list] = []
