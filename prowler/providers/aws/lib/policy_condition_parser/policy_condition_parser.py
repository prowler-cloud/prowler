# lista de cuentas y te devuelva las válidas
def is_account_only_allowed_in_condition(
    condition_statement: dict, source_account_list: str
):
    is_condition_valid = False
    valid_condition_options = {
        "StringEquals": [
            "aws:SourceAccount",
            "s3:ResourceAccount",
            "aws:PrincipalAccount",
        ],
        "StringLike": ["aws:SourceArn", "aws:PrincipalArn"],
        "ArnLike": ["aws:SourceArn", "aws:PrincipalArn"],
        "ArnEquals": ["aws:SourceArn", "aws:PrincipalArn"],
    }

    for condition_operator, condition_operator_key in valid_condition_options.items():
        if condition_operator in condition_statement:
            for value in condition_operator_key:
                if value in condition_statement[condition_operator]:
                    # values are a list
                    if isinstance(
                        condition_statement[condition_operator][value],
                        list,
                    ):
                        # if there is an arn/account without the source account -> we do not consider it safe
                        # here by default we assume is true and look for false entries
                        is_condition_valid = True
                        for item in condition_statement[condition_operator][value]:
                            for account in source_account_list:
                                if account not in item:
                                    is_condition_valid = False
                                    break
                            if is_condition_valid is False:
                                break
                    # value is a string
                    elif isinstance(
                        condition_statement[condition_operator][value],
                        str,
                    ):
                        for account in source_account_list:
                            if (
                                account
                                in condition_statement[condition_operator][value]
                            ):
                                is_condition_valid = True

    return is_condition_valid
