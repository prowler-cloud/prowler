#!/usr/bin/env python3

"""
Stank A Module that will grab the "call" definition for a particular
profile/definition, cache it and make it available to a smell
"""

import json
import logging
import hashlib
import os
import os.path
import time
import io
import csv
import collections

import pyjq
import sniffy

class Stank:

    def __init__(self, aws_session=None, call_def=None, region="us-west-1", **kwargs):

        self.logger = logging.getLogger("Stank")

        if aws_session is None or call_def is None:
            raise TypeError("Missing Required Definitions")

        self.aws_session = aws_session
        self.call_def = call_def
        self.kwargs = kwargs
        self.region = region

        self.account_id = kwargs.get("account_id",
                                     self.aws_session.client('sts').get_caller_identity()['Account'])

        self.call_string = "{}.{}.{}.{}.{}.{}.{}.{}".format(self.call_def["name"],
                                                            self.call_def["action"],
                                                            sorted(self.call_def.get("kwargs", dict())),
                                                            sorted(self.call_def.get("args", list())),
                                                            self.call_def.get("take", "all"),
                                                            self.region,
                                                            str(json.dumps(self.call_def.get("pre_call", {}), sort_keys=True, default=str)),
                                                            str(json.dumps(self.call_def.get("fo_def", {}), sort_keys=True, default=str))
                                                            )

        self.call_hash = hashlib.sha256(self.call_string.encode()).hexdigest()

        self.logger.debug("Call String : {}".format(self.call_string))

        if self.kwargs.get("cache_dir", None) is not None and os.path.isdir(self.kwargs["cache_dir"]) is True:
            self.logger.debug("Checking Cache")
            self.check_cache()
        else:
            self.logger.debug("Naked Load")
            self.data = self.load_stank(try_cache=False)

    def check_cache(self):

        account_cache_dir = os.path.join(self.kwargs["cache_dir"], self.account_id)

        expected_cache_file = os.path.join(account_cache_dir, "{}.json".format(self.call_hash))

        if os.path.isdir(account_cache_dir) is False:
            # Add Cache Subdirectory
            os.mkdir(account_cache_dir)

        if os.path.isfile(expected_cache_file):
            file_age = int(time.time()) - int(os.stat(expected_cache_file).st_ctime)

            if file_age > self.kwargs.get("cache_age", 21600):
                # File is too Old Let's Load one From load_Stank()
                self.data = self.load_stank(try_cache=True)
            else:
                # File is Young Enough
                with open(expected_cache_file) as ecf_obj:
                    try:
                        self.data = json.load(ecf_obj)
                    except Exception as cache_json_error:
                        self.logger.error("Unable to Load Cached File {} from Disk Making Call".format(expected_cache_file))
                        self.logger.debug("Error : {}".format(cache_json_error))
                        # Load Stank()
                    else:
                        self.logger.info("Loaded Cache of {} Seconds".format(file_age))
        else:
            # No Cache File Load from API
            self.data = self.load_stank(try_cache=True)

    def load_stank(self, try_cache=True):

        data = dict(result=dict())

        if "pre_call" in self.call_def.keys():
            # Do a Pre-Call
            self.logger.debug("Attempt a pre_call")
            pre_client = self.aws_session.client(self.call_def["pre_call"]["name"], region_name=self.region)

            pre_call_data = getattr(pre_client, self.call_def["pre_call"]["action"])(*self.call_def["pre_call"].get("args", list()),
                                                                                     **self.call_def["pre_call"].get("kwargs", list()))

            data["pre_call_data"] = pre_call_data

            self.logger.debug(data)

            # Allow a Delay if Neccessary
            time.sleep(self.call_def["pre_call"].get("delay", 10))

        # Do AWS Load
        this_client = self.aws_session.client(self.call_def["name"], region_name=self.region)

        if self.call_def.get("paginator", False) is False:
            niave_data = getattr(this_client, self.call_def["action"])(*self.call_def.get("args", list()),
                                                                       **self.call_def.get("kwags", dict()))
        else:
            plist = list()
            paginator = this_client.get_paginator(self.call_def["action"])

            for p in paginator.paginate():
                this_page = pyjq.all(self.call_def.get("paginator", False), p)

                self.logger.debug(this_page)
                self.logger.debug(plist)

                if len(this_page) > 0:

                    plist.extend(this_page)


            niave_data = plist


        if self.call_def.get("take", "all") != "all":
            self.logger.info("Taking a Subset of the Main Result")
            data["result"] = pyjq.all(self.call_def["take"], niave_data)
            self.logger.debug("Post take obj : {}".format(data["result"]))
        else:
            data["result"] = niave_data

        if isinstance(data["result"], collections.Iterable) and "fo_def" in self.call_def.keys():
            self.logger.info("Executing FODef Calls for Iterable Items")

            for index in range(0, len(data["result"])):
                if isinstance(data["result"][index], dict) is True:
                    fan_out_subject = data["result"][index]
                    for this_fo_def in self.call_def["fo_def"]:

                        this_fo_client = self.aws_session.client(this_fo_def["name"], region_name=self.region)

                        this_fo_data = getattr(this_client,
                                               this_fo_def["action"])(*sniffy.hydrate(this_fo_def.get("args", list()),
                                                                                      fan_out_subject),
                                                                       **sniffy.hydrate(this_fo_def.get("kwargs", dict()),
                                                                                        fan_out_subject)
                                                                      )

                        # Have Data Inject Back into Main Result
                        data["result"][index][this_fo_def["inname"]] = this_fo_data
                else:
                    self.logger.warning("Ignoring fodef directive for index'ed item {} as it's not a dictionary.".format(index))

        clean_data = json.loads(json.dumps(data, default=str, sort_keys=True))

        if try_cache is True:

            expected_cache_file = os.path.join(self.kwargs["cache_dir"],
                                               self.account_id,
                                               "{}.json".format(self.call_hash))

            with open(expected_cache_file, "w") as ecf_obj:
                json.dump(clean_data, ecf_obj)

        return clean_data

    def post_process(self, this_def=None):

        """
        Do Post Process Rule
        """

        rule_name = this_def["name"]
        rule_type = this_def["type"]
        rule_target = pyjq.first(this_def["field"], self.data["result"])

        self.logger.debug(this_def)
        self.logger.debug(rule_target)

        data_to_add = None

        if rule_type == "bcsv":
            data_to_add = list()

            # This is the b in bcsv
            csv_string_data = "".join(rule_target[2:-1]).replace("\\n", "\n")

            synthetic_field = io.StringIO(csv_string_data, newline="\n")

            self.logger.debug(synthetic_field )

            reader = csv.DictReader(synthetic_field)

            self.logger.debug(reader.line_num)

            for row in reader:
                self.logger.debug(row)
                data_to_add.append(row)

        # End Now Add It.
        if "post_process" not in self.data.keys():
            self.data["post_process"] = dict()

        self.data["post_process"][rule_name] = data_to_add

