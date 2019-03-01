#!/usr/bin/env python3

# Copyright 2019 Toni de la Fuente, Jonny Tyers

# Prowler is a tool that provides automate auditing and hardening guidance of an
# AWS account. It is based on AWS-CLI commands. It follows some guidelines
# present in the CIS Amazon Web Services Foundations Benchmark at:
# https://d0.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf

# Contact the author at https://blyx.com/contact
# and open issues or ask questions at https://github.com/toniblyx/prowler


# All CIS based checks in checks folder are licensed under a Creative Commons
# Attribution-NonCommercial-ShareAlike 4.0 International Public License.
# The link to the license terms can be found at
# https://creativecommons.org/licenses/by-nc-sa/4.0/legalcode
#
# Any other piece of code is licensed as Apache License 2.0 as specified in
# each file. You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0

# Prowler - Iron Maiden
#
# Walking through the city, looking oh so pretty
# I've just got to find my way
# See the ladies flashing
# All there legs and lashes
# I've just got to find my way...
import os
import re

VERSION = '3.0'
__dirname__ = os.path.dirname(os.path.abspath(__file__))

def read_group_file(group_file):
    """
    Read the group details from a group file and return as a dict. The
    return value will look like this:
        {
            "id": <value of GROUP_ID>,
            "number": <value of GROUP_NUMBER>,
            "title": <value of GROUP_TITLE>,
            "RUN_BY_DEFAULT": <boolean value of GROUP_RUN_BY_DEFAULT>,
            "checks": <array of check names>,
        }
    """
    with open(group_file, 'r') as f:
        lines = f.readlines()
        group_lines = filter(lambda x: re.compile(r'^GROUP_').match(x), lines)

        result = {}

        for line in group_lines:
            match = re.compile(r'^GROUP_(\w+)\[\d+\]=["\'](.*)[\'"]').match(line)
            if not match: continue

            group_var_name = match.group(1)
            group_var_value = match.group(2)

            if group_var_name == 'RUN_BY_DEFAULT':
                # turn 'Y' into True and anything else into False
                group_var_value = (group_var_name.lower() == 'y')

            if group_var_name == 'CHECKS':
                # turn 'check1,check2' into ['check1', 'check2']
                group_var_value = group_var_value.split(',')

            result[group_var_name.lower()] = group_var_value

        return result

def read_check_file(check_file):
    """
    Read the check details from a check file and return as a dict. The
    return value will look like this:
        {
            "name": <name of check file>,
            "id": <value of CHECK_ID>,
            "title": <value of CHECK_TITLE>,
            "scored": <value of CHECK_SCORED>,
            "type": <value of CHECK_TYPE>,
            "alternate": <value of CHECK_ALTERNATE>,
        }
    """
    with open(check_file, 'r') as f:
        lines = f.readlines()
        check_lines = filter(lambda x: re.compile(r'^CHECK_').match(x), lines)

        name = None
        result = {}

        for line in check_lines:
            match = re.compile(r'CHECK_(\w+)_(\w+)="?(.*)"?\b').match(line)
            if not match: continue

            check_var_name = match.group(1)
            check_var_name2 = match.group(2)
            check_var_value = match.group(3)

            if name is None:
                name = check_var_name2
            else:
                # if this is a CHECK_ALTERNATE line, we name2 with value,
                # swapping the model of the old shell-based prowler
                if line.startswith('CHECK_ALTERNATE_'):
                    name = check_var_value
                    check_var_name2 = name
                    check_var_value = check_var_name2

                # verify that the name is the same; otherwise fail
                if check_var_name2 != name:
                    raise ValueError('name '+check_var_name2+' for '+check_file+' line "'+line+'" does not match previous name "'+name+'"')

            result[check_var_name.lower()] = check_var_value

        result['name'] = name
        return result

# todo: parse argumnets

checks_dir = os.path.join(__dirname__, 'checks')
check_filenames =  filter(
    lambda x: x.startswith('check') and 'sample' not in x,
    os.listdir(checks_dir)
)
checks = map(lambda x: os.path.join(checks_dir, x), check_filenames)

groups_dir = os.path.join(__dirname__, 'groups')
group_filenames =  filter(
    lambda x: x.startswith('group') and 'sample' not in x,
    os.listdir(groups_dir)
)
groups = map(lambda x: os.path.join(groups_dir, x), group_filenames)

for c in checks:
    print(read_check_file(c))

for g in groups:
    print(read_group_file(g))
