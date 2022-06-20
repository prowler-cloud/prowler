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
