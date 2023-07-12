def condition_parser(condition_statement: dict, source_account: str):
    is_condition_valid = False
    valid_condition_options = {
        "StringEquals": "aws:SourceAccount",
        "ArnLike": "aws:SourceArn",
        "ArnEquals": "aws:SourceArn",
    }
    for condition_operator, condition_operator_key in valid_condition_options.items():
        if condition_operator in condition_statement:
            if condition_operator_key in condition_statement[condition_operator]:
                # values are a list
                if isinstance(
                    condition_statement[condition_operator][condition_operator_key],
                    list,
                ):
                    # if there is an arn/account without the source account -> we do not consider it safe
                    # here by default we assume is true and look for false entries
                    is_condition_valid = True
                    for item in condition_statement[condition_operator][
                        condition_operator_key
                    ]:
                        if source_account not in item:
                            is_condition_valid = False
                            break
                # value is a string
                elif isinstance(
                    condition_statement[condition_operator][condition_operator_key], str
                ):
                    if (
                        source_account
                        in condition_statement[condition_operator][
                            condition_operator_key
                        ]
                    ):
                        is_condition_valid = True

    return is_condition_valid
