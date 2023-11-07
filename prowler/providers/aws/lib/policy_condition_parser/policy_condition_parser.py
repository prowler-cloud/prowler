def is_account_only_allowed_in_condition(
    condition_statement: dict, source_account: str
):
    """
    is_account_only_allowed_in_condition parses the IAM Condition policy block and returns True if the source_account passed as argument is within, False if not.

    @param condition_statement: dict with an IAM Condition block, e.g.:
        {
            "StringLike": {
                "AWS:SourceAccount": 111122223333
            }
        }

    @param source_account: str with a 12-digit AWS Account number, e.g.: 111122223333
    """
    is_condition_valid = False

    # The conditions must be defined in lowercase since the context key names are not case-sensitive.
    # For example, including the aws:SourceAccount context key is equivalent to testing for AWS:SourceAccount
    # https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition.html
    valid_condition_options = {
        "StringEquals": [
            "aws:sourceaccount",
            "aws:sourceowner",
            "s3:resourceaccount",
            "aws:principalaccount",
            "aws:resourceaccount",
            "aws:sourcearn",
        ],
        "StringLike": [
            "aws:sourceaccount",
            "aws:sourceowner",
            "aws:sourcearn",
            "aws:principalarn",
            "aws:resourceaccount",
            "aws:principalaccount",
        ],
        "ArnLike": ["aws:sourcearn", "aws:principalarn"],
        "ArnEquals": ["aws:sourcearn", "aws:principalarn"],
    }

    for condition_operator, condition_operator_key in valid_condition_options.items():
        if condition_operator in condition_statement:
            for value in condition_operator_key:
                # We need to transform the condition_statement into lowercase
                condition_statement[condition_operator] = {
                    k.lower(): v
                    for k, v in condition_statement[condition_operator].items()
                }

                if value in condition_statement[condition_operator]:
                    # values are a list
                    if isinstance(
                        condition_statement[condition_operator][value],
                        list,
                    ):
                        # if there is an arn/account without the source account -> we do not consider it safe
                        # here by default we assume is true and look for false entries
                        is_condition_key_restrictive = True
                        for item in condition_statement[condition_operator][value]:
                            if source_account not in item:
                                is_condition_key_restrictive = False
                                break
                        if is_condition_key_restrictive:
                            is_condition_valid = True

                    # value is a string
                    elif isinstance(
                        condition_statement[condition_operator][value],
                        str,
                    ):
                        if (
                            source_account
                            in condition_statement[condition_operator][value]
                        ):
                            is_condition_valid = True

    return is_condition_valid
