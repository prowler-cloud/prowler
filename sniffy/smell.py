#!/usr/bin/evn python3

"""
Smell: Loads a Particular Check and Validates it.
"""

import logging
import json
import re
import datetime
import time

import yaml
import pyjq

import sniffy


class Smell:

    _avail_platforms = ["aws"]

    def __init__(self, filepath=None,
                 check_data=None,
                 aws_session=None,
                 account_id=None,
                 **kwargs):

        self.logger = logging.getLogger("Smell")
        self.kwargs = kwargs

        self.aws_session = aws_session
        self.account_id = account_id

        if filepath is not None:
            self.data = self.load_file(filepath)
        elif check_data is not None:
            self.data = check_data

        self.id = self.data["check_id"]

    def load_stank(self):

        """
        Load the Stank object(s) Needed for the Check
        :return:
        """

        if self.data.get("regions", True) is True or self.data.get("regions", True) == "all":
            regions = self.kwargs["aws_session"].get_ailable_regions(self.data["call"]["name"])

        elif isinstance(self.data.get("regions", True), str):
            regions = [self.data["regions"]]
        elif isinstance(self.data.get("regions", True), (list,tuple)):
            regions = self.data["regions"]
        else:
            raise TypeError("Unknown Regions Specification")

        self.stank_data = dict()

        for this_region in regions:
            # Load Stankload_smell
            self.stank_data[this_region] = sniffy.Stank(region=this_region,
                                                        aws_session=self.aws_session,
                                                        call_def=self.data["call"],
                                                        cache_dir=self.kwargs.get("cache_dir", None))
    def do_post_processing(self):

        """
        For Every Region Load Process
        :return:
        """

        # Post Process
        for process_def in self.data["post_process"]:
            for region, stank_obj in self.stank_data.items():
                stank_obj.post_process(this_def=process_def)


    def compare_logic(self, comparison=None, this_item=None):

        """
        Comparison Logic PassThrough
        Does Recursive Checks for "subcompare"

        returns a pass & pass reason

        :return:
        """
        pfi = "pass"
        fail_reason = None

        this_type = comparison.get("type", "str")
        # Compare Object Pull

        if "comp_jq" in comparison.keys():
            compare_item = pyjq.one(comparison["comp_jq"], this_item["data"])
        else:
            raise NotImplementedError("Compare_itenm strategy not Implemented")

        # Any Additional Formatting
        if this_type == "str":
            compare_item = str(compare_item)
        elif this_type == "time":
            # Always A Timestamp
            try:
                compare_item = int(datetime.datetime.strptime(str(compare_item),
                                                              comparison["time_format"]).timestamp())
            except Exception as error:
                self.logger.error(compare_item)
                self.logger.debug(this_item)
                self.logger.debug(comparison)
                raise error
        else:
            raise NotImplementedError("Unimplemented Type : {}".format(this_type))

        this_passed_so_far = "pass"
        # Defaults
        if "time_older" in comparison.keys() and this_type == "time":
            if int(time.time()) - compare_item < comparison["time_older"]:
                # Time is Too New
                this_passed_so_far = "fail"
                fail_reason = comparison.get("fail_reason", "Failed time_older Check")
        elif "time_newer" in comparison.keys() and this_type == "time":
            if int(time.time()) - compare_item > comparison["time_newer"]:
                # Time is Too New
                this_passed_so_far = "fail"
                fail_reason = comparison.get("fail_reason", "Failed time_newer Check")
        elif "rematch" in comparison.keys() and this_type == "str":
            if re.match(comparison["rematch"], compare_item) is None:
                this_passed_so_far = "fail"
                fail_reason = comparison.get("fail_reason", "Failed rematch Check")
        elif "renomatch" in comparison.keys() and this_type == "str":
            if re.match(comparison["renomatch"], compare_item) is not None:
                this_passed_so_far = "fail"
                fail_reason = comparison.get("fail_reason", "Failed renomatch Check")
        else:
            raise NotImplementedError("Unknown Comparison Strategy")

        self.logger.debug(comparison)
        if this_passed_so_far == "fail":
            self.logger.debug("fail")
            if "subfailcompare" in comparison.keys():
                pfi, fail_reason = self.compare_logic(comparison=comparison["subfailcompare"], this_item=this_item)
            else:
                pfi = "fail"
        elif "subpasscompare" in comparison.keys():
            self.logger.debug("pass : subpasscompre")
            pfi, fail_reason = self.compare_logic(comparison=comparison["subpasscompare"], this_item=this_item)

        return pfi, fail_reason

    def execute(self):

        """
        Execute Check
        :return:
        """

        # Load Stank Data (Make API Calls Per Region)
        self.load_stank()

        # Post Process Add Any additional Items
        self.do_post_processing()

        # Record Pass/Fail/Info
        pfi_log = list()

        # Do Check
        for region, stank_obj in self.stank_data.items():
            #stank_obj.post_process(this_def=process_def)

            # Get Itemsem
            rule_definition = self.data["rule"]
            item_def = rule_definition["item"]

            if "jqiter" in rule_definition["item"].keys():

                for potential_item in pyjq.all(item_def["jqiter"], stank_obj.data):

                    eval_item = False

                    if "subject_jq" in item_def["target_strategy"].keys():
                        this_item_subject = str(pyjq.first(item_def["target_strategy"]["subject_jq"], potential_item))
                    else:
                        self.logger.error("Subject Strategy Not Implemented")
                        this_item_subject = "Not Specified"


                    if item_def["target_strategy"].get("strat_type", "jqregex"):

                        this_ts_jq = item_def["target_strategy"]["target_jq"]
                        this_ts_regex = item_def["target_strategy"].get("target_regex", False)
                        this_ts_noregex = item_def["target_strategy"].get("target_noregex", False)

                        # Target Definition
                        try:
                            jq_pulled_string = pyjq.one(this_ts_jq, potential_item)
                        except Exception as bad_parse_error:
                            self.logger.warning("Error on JQRegex Find It")
                            self.logger.debug("Error : {}".format(bad_parse_error))
                        else:
                            if this_ts_regex is False and this_ts_noregex is False:
                                if jq_pulled_string is not None:
                                    eval_item = True
                            elif this_ts_regex is not False:
                                if re.match(this_ts_regex, str(jq_pulled_string)) is not None:
                                    eval_item = True
                            elif this_ts_noregex is not False:
                                if re.match(this_ts_noregex, str(jq_pulled_string)) is None:
                                    eval_item = True

                    if eval_item is True:

                        # Found a Match let's add it.
                        pfi_log.append({"subject": this_item_subject,
                                        "data" : potential_item,
                                        "pfi" : "toeval",
                                        "pfi_reason" : "to be determined",
                                        "region" : region,
                                        "account_id" : self.account_id,
                                        "check_id" : self.id,
                                        "check_title" : self.data.get("check_title", "Untitled Check"),
                                        "platform": self.data.get("platform", "Unspecified Resource Used")})
                    else:
                        self.logger.debug("Not evaluating {} ".format(this_item_subject))
            else:
                raise NotImplementedError("This Subject Method Not Yet Supported")


        ## Okay I now have all of the Subjects I wish to Evaluate
        for this_item_index in range(0, len(pfi_log)):

            this_one_item = pfi_log[this_item_index]

            self.logger.info("Evaluating Subject {subject} from {region}".format(**this_one_item))

            pfi = "pass"
            pfi_reason = rule_definition.get("pass_reason", "No Pass Reason Specified (Default Pass)")

            for this_comparison in rule_definition["compare"]:

                psf, psf_reason = self.compare_logic(comparison=this_comparison, this_item=this_one_item)

                if psf == "fail":
                    pfi = psf
                    pfi_reason = psf_reason
                    break
                else:
                    # Try the next check in the series
                    continue

            # I've a result
            pfi_log[this_item_index]["pfi"] = pfi
            pfi_log[this_item_index]["pfi_reason"] = pfi_reason

        return pfi_log

    def validate(self):

        """
        Validate that the Check makes Logical Sense
        :return:
        """

        valid = True

        if self.aws_session is None:
            self.logger.error("AWS Session is Not Given")
            valid = False

        if isinstance(self.account_id, int) is None:
            self.logger.error("AWS Account Id is Not Given")
            valid = False

        if "check_id" not in self.data.keys():
            self.logger.error("Check Missing check_id")
            valid = False

        if "check_title" not in self.data.keys():
            self.logger.error("Check Missing check_title")
            valid = False

        if isinstance(self.data.get("check_groups", list()), (tuple,list)) is False:
            self.logger.error("check_groups is wrong type")
            valid = False

        if self.data.get("paltform", "aws") not in ["aws"]:
            self.logger.error("Platform type of : {} unknown".format(self.data.get("platform", "aws")))
            valid = False

        if "call" not in self.data.keys():
            self.logger.error("No Call Data Specified.")
            valid = False

        return valid

    def load_file(self, filepath):

        if filepath.endswith(".json"):
            try:
                with open(filepath) as fpo:
                    data = json.load(fpo)
            except Exception as json_error:
                self.logger.error("File {} Has JSON Error".format(json_error))
                raise json_error
        elif filepath.endswith(".yaml"):
            try:
                with open(filepath) as fpo:
                    data = yaml.safe_load(fpo)
            except Exception as yaml_error:
                self.logger.error("File {} Has YAML Error".format(yaml_error))
                raise yaml_error
        else:
            raise TypeError("File {} Needs to be a JSON or YAML file.".format(filepath))

        return data
