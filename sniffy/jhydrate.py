#!/usr/bin/env python3

"""
A Function that Takes a String, Tulple, or Dict; with Items
and hydrates them
"""

import json
import jinja2
import logging

def hydrate(unhyd, items, **kwargs):

    """
    :param unhyd: Unhydrated Object
    :param items: Items to make Available for Hydration
    :param kwargs:  Additional Options
    :return:
    """

    logger = logging.getLogger("jhydrate")

    template_string = unhyd
    do_json = False

    if isinstance(unhyd, (dict, list)) is True:
        template_string = json.dumps(unhyd)
        do_json = True


    template = jinja2.Environment(loader=jinja2.BaseLoader).from_string(template_string)

    logger.debug("template {}".format(template_string))
    logger.debug("items {}".format(items))

    rendered_string = template.render(**items)

    if do_json is True:
        return_obj = json.loads(rendered_string)
    else:
        return_obj = rendered_string

    return return_obj


