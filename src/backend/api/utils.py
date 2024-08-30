def merge_dicts(default_dict: dict, replacement_dict: dict) -> dict:
    """
    Recursively merge two dictionaries, using `default_dict` as the base and `replacement_dict` for overriding values.

    Args:
        default_dict (dict): The base dictionary containing default key-value pairs.
        replacement_dict (dict): The dictionary containing values that should override those in `default_dict`.

    Returns:
        dict: A new dictionary containing all keys from `default_dict` with values from `replacement_dict` replacing
              any overlapping keys. If a key in both `default_dict` and `replacement_dict` contains dictionaries,
              this function will merge them recursively.
    """
    result = default_dict.copy()

    for key, value in replacement_dict.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            if value:
                result[key] = merge_dicts(result[key], value)
            else:
                result[key] = value
        else:
            result[key] = value

    return result
