class RoleArnParsingFailedMissingFields(Exception):
    # The ARN contains a number of fields different than six separated by :"
    def __init__(self):
        self.message = "The assumed role ARN contains an invalid number of fields separated by : or it does not start by arn, please input a valid ARN"
        super().__init__(self.message)


class RoleArnParsingIAMRegionNotEmpty(Exception):
    # The ARN contains a non-empty value for region, since it is an IAM ARN is not valid
    def __init__(self):
        self.message = "The assumed role ARN contains a non-empty value for region, since it is an IAM ARN is not valid, please input a valid ARN"
        super().__init__(self.message)


class RoleArnParsingPartitionEmpty(Exception):
    # The ARN contains an empty value for partition
    def __init__(self):
        self.message = "The assumed role ARN does not contain a value for partition, please input a valid ARN"
        super().__init__(self.message)


class RoleArnParsingServiceNotIAMnorSTS(Exception):
    def __init__(self):
        self.message = "The assumed role ARN contains a value for service distinct than IAM or STS, please input a valid ARN"
        super().__init__(self.message)


class RoleArnParsingServiceNotSTS(Exception):
    def __init__(self):
        self.message = "The assumed role ARN contains a value for service distinct than STS, please input a valid ARN"
        super().__init__(self.message)


class RoleArnParsingInvalidAccountID(Exception):
    def __init__(self):
        self.message = "The assumed role ARN contains a value for account id empty or invalid, a valid account id must be composed of 12 numbers, please input a valid ARN"
        super().__init__(self.message)


class RoleArnParsingInvalidResourceType(Exception):
    def __init__(self):
        self.message = "The assumed role ARN contains a value for resource type different than role, please input a valid ARN"
        super().__init__(self.message)


class RoleArnParsingEmptyResource(Exception):
    def __init__(self):
        self.message = "The assumed role ARN does not contain a value for resource, please input a valid ARN"
        super().__init__(self.message)
