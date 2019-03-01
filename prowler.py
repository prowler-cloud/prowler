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
import simplejson
import subprocess

VERSION = '3.0'
__dirname__ = os.path.dirname(os.path.abspath(__file__))

GROUP_MATCHER = re.compile(r'^GROUP_(\w+)\[\d+\]=["\'](.*)[\'"]')
CHECK_MATCHER = re.compile(r'CHECK_(\w+)_(\w+)="?(.*)"?\b')


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
            match = GROUP_MATCHER.match(line)
            if not match:
                continue

            group_var_name = match.group(1)
            group_var_value = match.group(2)

            if group_var_name == 'RUN_BY_DEFAULT':
                # turn 'Y' into True and anything else into False
                group_var_value = (group_var_name.lower() == 'y')

            if group_var_name == 'CHECKS':
                # turn 'check1,check2' into ['check1', 'check2']
                group_var_value = group_var_value.split(',')

            result[group_var_name.lower()] = group_var_value

        result['path'] = group_file
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
            match = CHECK_MATCHER.match(line)
            if not match:
                continue

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
                    raise ValueError('name ' + check_var_name2 + ' for '
                            + check_file + ' line "' + line +
                            '" does not match previous name "' + name + '"')

            result[check_var_name.lower()] = check_var_value

        result['name'] = name
        result['path'] = check_file
        return result


def find_awscli():
    return subprocess.run(
        ['which', 'aws'],
        text=True,
        check=True,
        capture_output=True,
    ).stdout.strip()


def execute_check(check_name):
    # look for the check_name in the checks dict
    if not checks.get(check_name):
        raise ValueError('could not find check "'+check_name+'"')

    check = checks[check_name]

    result = subprocess.run(
        [os.path.join(__dirname__, 'run-check'), check_name, check['path']],
        capture_output=True,
        text=True,
        env=env,
    )

    output = []
    for line in result.stdout.split('\n'):
        if not line.strip():
            continue # skip blank lines

        line_output = simplejson.loads(line)

        if result.stderr:
            line_output['Message'] = '\n'.join([line_output['Message'], result.stderr.strip()])

        output.append(line_output)

    return output


def read_check_files():
    checks_dir = os.path.join(__dirname__, 'checks')
    check_filenames = filter(
        lambda x: x.startswith('check') and 'sample' not in x,
        os.listdir(checks_dir)
    )
    check_paths = map(lambda x: os.path.join(checks_dir, x), check_filenames)

    checks = {}
    for c in check_paths:
        check = read_check_file(c)
        checks[check['name']] = check

    return checks


def read_group_files():
    groups_dir = os.path.join(__dirname__, 'groups')
    group_filenames = filter(
        lambda x: x.startswith('group') and 'sample' not in x,
        os.listdir(groups_dir)
    )
    group_paths = map(lambda x: os.path.join(groups_dir, x), group_filenames)

    groups = {}
    for g in group_paths:
        group = read_group_file(g)
        groups[group['name']] = group

    return groups


# todo: parse argumnets

# prepare environment that we'll run checks in
# set MODE to "json" regardless of how we were called, so we can
# reliably parse the result
env = dict(os.environ)
env['MODE'] = 'json'
env['AWSCLI'] = find_awscli()

checks = read_check_files()

print(simplejson.dumps(execute_check('check112')))
