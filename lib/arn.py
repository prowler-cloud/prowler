from arnparse import arnparse


class RoleArnParsingFailedMissingFields(Exception):
    # The arn contains a numberof fields different than six separated by :"
    def __init__(self):
        self.message = "The assumed role arn contains a number of fields different than six separated by :, please input a valid arn"
        super().__init__(self.message)


class RoleArnParsingIAMRegionNotEmpty(Exception):
    # The arn contains a non-empty value for region, since it is an IAM arn is not valid
    def __init__(self):
        self.message = "The assumed role arn contains a non-empty value for region, since it is an IAM arn is not valid, please input a valid arn"
        super().__init__(self.message)


class RoleArnParsingPartitionEmpty(Exception):
    # The arn contains an empty value for partition
    def __init__(self):
        self.message = "The assumed role arn does not contain a value for partition, please input a valid arn"
        super().__init__(self.message)


class RoleArnParsingServiceNotIAM(Exception):
    def __init__(self):
        self.message = "The assumed role arn contains a value for service distinct than iam, please input a valid arn"
        super().__init__(self.message)


class RoleArnParsingInvalidAccountID(Exception):
    def __init__(self):
        self.message = "The assumed role arn contains a value for account id empty or invalid, a valid account id must be composed of 12 numbers, please input a valid arn"
        super().__init__(self.message)


class RoleArnParsingInvalidResourceType(Exception):
    def __init__(self):
        self.message = "The assumed role arn contains a value for resource type different than role, please input a valid arn"
        super().__init__(self.message)


class RoleArnParsingEmptyResource(Exception):
    def __init__(self):
        self.message = "The assumed role arn does not contain a value for resource, please input a valid arn"
        super().__init__(self.message)


def arn_parsing(arn):
    # check for number of fields, must be six
    if len(arn.split(":")) != 6:
        raise RoleArnParsingFailedMissingFields
    else:
        arn_parsed = arnparse(arn)
        # First check if region is empty (in IAM arns region is always empty)
        if arn_parsed.region != None:
            raise RoleArnParsingIAMRegionNotEmpty
        else:
            # check if needed fields are filled:
            # - partition
            # - service
            # - account_id
            # - resource_type
            # - resource
            if arn_parsed.partition == None:
                raise RoleArnParsingPartitionEmpty
            elif arn_parsed.service != "iam":
                raise RoleArnParsingServiceNotIAM
            elif (
                arn_parsed.account_id == None
                or len(arn_parsed.account_id) != 12
                or not arn_parsed.account_id.isnumeric()
            ):
                raise RoleArnParsingInvalidAccountID
            elif arn_parsed.resource_type != "role":
                raise RoleArnParsingInvalidResourceType
            elif arn_parsed.resource == "":
                raise RoleArnParsingEmptyResource
            else:
                return arn_parsed
