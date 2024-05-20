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
    unrolled_items = ""
    separator = "|"
    if tags and tags != [{}] and tags != [None]:
        for item in tags:
            # Check if there are tags in list
            if isinstance(item, dict):
                for key, value in item.items():
                    if not unrolled_items:
                        # Check the pattern of tags (Key:Value or Key:key/Value:value)
                        if "Key" != key and "Value" != key:
                            unrolled_items = f"{key}={value}"
                        else:
                            if "Key" == key:
                                unrolled_items = f"{value}="
                            else:
                                unrolled_items = f"{value}"
                    else:
                        if "Key" != key and "Value" != key:
                            unrolled_items = (
                                f"{unrolled_items} {separator} {key}={value}"
                            )
                        else:
                            if "Key" == key:
                                unrolled_items = (
                                    f"{unrolled_items} {separator} {value}="
                                )
                            else:
                                unrolled_items = f"{unrolled_items}{value}"
            elif not unrolled_items:
                unrolled_items = f"{item}"
            else:
                unrolled_items = f"{unrolled_items} {separator} {item}"

    return unrolled_items


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
