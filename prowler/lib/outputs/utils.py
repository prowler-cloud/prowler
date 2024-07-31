def unroll_list(listed_items: list, separator: str = "|"):
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


def unroll_tags(tags: list):
    if tags and tags != [{}] and tags != [None]:
        if "key" in tags[0]:
            return {item["key"]: item["value"] for item in tags}
        elif "Key" in tags[0]:
            return {item["Key"]: item["Value"] for item in tags}
        else:
            return {key: value for d in tags for key, value in d.items()}
    return {}


def unroll_dict(dict: dict):
    unrolled_items = ""
    separator = "|"
    for key, value in dict.items():
        if isinstance(value, list):
            value = ", ".join(value)
        if not unrolled_items:
            unrolled_items = f"{key}: {value}"
        else:
            unrolled_items = f"{unrolled_items} {separator} {key}: {value}"

    return unrolled_items


def unroll_dict_to_list(dict: dict):
    dict_list = []
    for key, value in dict.items():
        if isinstance(value, list):
            value = ", ".join(value)
            dict_list.append(f"{key}: {value}")
        else:
            dict_list.append(f"{key}: {value}")

    return dict_list


def parse_json_tags(tags: list):
    dict_tags = {}
    if tags and tags != [{}] and tags != [None]:
        for tag in tags:
            if "Key" in tag and "Value" in tag:
                dict_tags[tag["Key"]] = tag["Value"]
            else:
                dict_tags.update(tag)

    return dict_tags


def parse_html_string(str: str):
    string = ""
    for elem in str.split(" | "):
        if elem:
            string += f"\n&#x2022;{elem}\n"

    return string
