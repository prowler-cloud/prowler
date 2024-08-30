def unroll_list(listed_items: list, separator: str = "|") -> str:
    """
    Unrolls a list of items into a single string, separated by a specified separator.

    Args:
        listed_items (list): The list of items to be unrolled.
        separator (str, optional): The separator to be used between the items. Defaults to "|".

    Returns:
        str: The unrolled string.

    Examples:
        >>> unroll_list(['apple', 'banana', 'orange'])
        'apple | banana | orange'

        >>> unroll_list(['apple', 'banana', 'orange'], separator=',')
        'apple, banana, orange'

        >>> unroll_list([])
        ''
    """
    unrolled_items = ""
    if listed_items:
        for item in listed_items:
            if not unrolled_items:
                unrolled_items = f"{item}"
            else:
                if separator == "|":
                    unrolled_items = f"{unrolled_items} {separator} {item}"
                else:
                    unrolled_items = f"{unrolled_items}{separator} {item}"

    return unrolled_items


def unroll_tags(tags: list) -> dict:
    """
    Unrolls a list of tags into a dictionary.

    Args:
        tags (list): A list of tags.

    Returns:
        dict: A dictionary containing the unrolled tags.

    Examples:
        >>> tags = [{"key": "name", "value": "John"}, {"key": "age", "value": "30"}]
        >>> unroll_tags(tags)
        {'name': 'John', 'age': '30'}

        >>> tags = [{"Key": "name", "Value": "John"}, {"Key": "age", "Value": "30"}]
        >>> unroll_tags(tags)
        {'name': 'John', 'age': '30'}

        >>> tags = [{"key": "name"}]
        >>> unroll_tags(tags)
        {'name': ''}

        >>> tags = [{"Key": "name"}]
        >>> unroll_tags(tags)
        {'name': ''}

        >>> tags = [{"name": "John", "age": "30"}]
        >>> unroll_tags(tags)
        {'name': 'John', 'age': '30'}

        >>> tags = []
        >>> unroll_tags(tags)
        {}

        >>> tags = {"name": "John", "age": "30"}
        >>> unroll_tags(tags)
        {'name': 'John', 'age': '30'}

        >>> tags = ["name", "age"]
        >>> unroll_tags(tags)
        {'name': '', 'age': ''}
    """
    if tags and tags != [{}] and tags != [None] and tags != []:
        if isinstance(tags, dict):
            return tags
        if isinstance(tags[0], str) and len(tags) > 0:
            return {tag: "" for tag in tags}
        if "key" in tags[0]:
            return {item["key"]: item.get("value", "") for item in tags}
        elif "Key" in tags[0]:
            return {item["Key"]: item.get("Value", "") for item in tags}
        else:
            return {key: value for d in tags for key, value in d.items()}
    return {}


def unroll_dict(dict: dict, separator: str = "=") -> str:
    """
    Unrolls a dictionary into a string representation.

    Args:
        dict (dict): The dictionary to be unrolled.

    Returns:
        str: The unrolled string representation of the dictionary.

    Examples:
        >>> my_dict = {'name': 'John', 'age': 30, 'hobbies': ['reading', 'coding']}
        >>> unroll_dict(my_dict)
        'name: John | age: 30 | hobbies: reading, coding'
    """

    unrolled_items = ""
    for key, value in dict.items():
        if isinstance(value, list):
            value = ", ".join(value)
        if not unrolled_items:
            unrolled_items = f"{key}{separator}{value}"
        else:
            unrolled_items = f"{unrolled_items} | {key}{separator}{value}"

    return unrolled_items


def unroll_dict_to_list(dict: dict) -> list:
    """
    Unrolls a dictionary into a list of key-value pairs.

    Args:
        dict (dict): The dictionary to be unrolled.

    Returns:
        list: A list of key-value pairs, where each pair is represented as a string.

    Examples:
        >>> my_dict = {'name': 'John', 'age': 30, 'hobbies': ['reading', 'coding']}
        >>> unroll_dict_to_list(my_dict)
        ['name: John', 'age: 30', 'hobbies: reading, coding']
    """

    dict_list = []
    for key, value in dict.items():
        if isinstance(value, list):
            value = ", ".join(value)
            dict_list.append(f"{key}:{value}")
        else:
            dict_list.append(f"{key}:{value}")

    return dict_list


def parse_json_tags(tags: list) -> dict[str, str]:
    """
    Parses a list of JSON tags and returns a dictionary of key-value pairs.

    Args:
        tags (list): A list of JSON tags.

    Returns:
        dict: A dictionary containing the parsed key-value pairs from the tags.

    Examples:
        >>> tags = [
        ...     {"Key": "Name", "Value": "John"},
        ...     {"Key": "Age", "Value": "30"},
        ...     {"Key": "City", "Value": "New York"}
        ... ]
        >>> parse_json_tags(tags)
        {'Name': 'John', 'Age': '30', 'City': 'New York'}
    """

    dict_tags = {}
    if tags and tags != [{}] and tags != [None]:
        for tag in tags:
            if "Key" in tag and "Value" in tag:
                dict_tags[tag["Key"]] = tag["Value"]
            else:
                dict_tags.update(tag)

    return dict_tags


def parse_html_string(str: str) -> str:
    """
    Parses a string and returns a formatted HTML string.

    This function takes an input string and splits it using the delimiter " | ".
    It then formats each element of the split string as a bullet point in HTML format.

    Args:
        str (str): The input string to be parsed.

    Returns:
        str: The formatted HTML string.

    Example:
        >>> parse_html_string("item1 | item2 | item3")
        '\n&#x2022;item1\n\n&#x2022;item2\n\n&#x2022;item3\n'
    """
    string = ""
    for elem in str.split(" | "):
        if elem:
            string += f"\n&#x2022;{elem}\n"

    return string
