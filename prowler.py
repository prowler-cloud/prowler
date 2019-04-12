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
import sys
import tempfile
import argparse
from datetime import datetime
import simplejson
import subprocess
import time
import base64

from colorama import Fore, Style

VERSION = '3.0-python'
__dirname__ = os.path.dirname(os.path.abspath(__file__))

GROUP_MATCHER = re.compile(r'^GROUP_(\w+)\[\d+\]=["\'](.*)[\'"]')
CHECK_MATCHER = re.compile(r'CHECK_(\w+)_(\w+)="?(.*)"?\b')

credential_report_generated = False
credential_report_temp_file = tempfile.mkstemp()[1]


def run(cmd, text=True, check=True):
    """
    Run a command, printing stderr (useful if it fails).
    """
    result = subprocess.run(
        cmd,
        text=text,
        check=False,
        capture_output=True,
    )

    if result.stderr:
        print(result.stderr)

    if check:
        result.check_returncode()
    
    return result.stdout.rstrip() # strip trailing newline in particular


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
            "alternateNames": [<CHECK_ALTERNATE check name>],
        }
    """
    with open(check_file, 'r') as f:
        lines = f.readlines()
        check_lines = filter(lambda x: x.startswith('CHECK_'), lines)

        name = None
        alternateNames = []
        result = {}

        for line in check_lines:
            match = CHECK_MATCHER.match(line)
            if not match:
                continue

            check_var_name = match.group(1)
            check_var_name2 = match.group(2)
            check_var_value = match.group(3)

            # if this is a CHECK_ALTERNATE line, we add
            # the alternate check name to the alternateNamess list
            if check_var_name == 'ALTERNATE':
                # under old prowler:
                #   name = 'ALTERNATE'
                #   name2 = name of alternate check
                #   value = name of this check
                alternateNames.append(check_var_name2)

            else:
                if name is None:
                    name = check_var_name2
                else:

                    # verify that the name is the same; otherwise fail
                    if check_var_name2 != name:
                        raise ValueError('name ' + check_var_name2 + ' for '
                                + check_file + ' line "' + line +
                                '" does not match previous name "' + name + '"')

                result[check_var_name.lower()] = check_var_value

        result['name'] = name
        result['alternateNames'] = alternateNames
        result['path'] = check_file
        return result


def aws(*args, check=True):
    #print('aws, about to run', [ find_awscli() ] + list(args))
    r = run([ find_awscli() ] + list(args), check=check)
    #print(' -> ', r)
    return r

def find_awscli():
    return run(['which', 'aws'])


def generate_credential_report():
    def gcr_status():
        return aws(
            'iam',
            'generate-credential-report',
            '--output',
            'text',
            '--query',
            'State',
            profile_opt,
            '--region',
            args.region
        )

    while gcr_status() != 'COMPLETE':
        time.sleep(3)

    cred_report_b64 = aws(
        'iam',
        'get-credential-report',
        '--output',
        'text',
        '--query',
        'Content',
        profile_opt,
        '--region',
        args.region
    )

    with open(credential_report_temp_file, 'w') as f:
        decoded = base64.b64decode(cred_report_b64)
        f.write(str(decoded, 'utf-8'))


def execute_check(check_name):
    global credential_report_generated

    check = None

    # check whether this has an alternate name, if it does, execute it
    matching_alternates = list(filter(lambda x: check_name in x['alternateNames'], checks.values()))
    if len(matching_alternates) > 1:
        raise ValueError('check '+check_name+' matched more than one check')

    elif len(matching_alternates) == 1:
        check = matching_alternates[0]

    else:
        # look for the check_name in the checks dict
        if not checks.get(check_name):
            raise ValueError('could not find check "'+check_name+'"')
        check = checks[check_name]

    if check['name'].startswith('check1'):
        if not credential_report_generated:
            generate_credential_report()
            credential_report_generated = True

    result = subprocess.run(
        [os.path.join(__dirname__, 'run-check'), check_name, check['path']],
        capture_output=True,
        text=True,
        env=env,
    )

    # a check might emit more than one line (sadly)
    output = []
    for line in result.stdout.split('\n'):
        if not line.strip():
            continue # skip blank lines

        line_output = simplejson.loads(line)

        output.append(line_output)

    if result.stderr:
        print(result.stderr, file=sys.stderr)
        #line_output['Message'] = '\n'.join([line_output['Message'], result.stderr.strip()])

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
        groups[group['id']] = group

    return groups


# todo: parse argumnets
parser = argparse.ArgumentParser(description="""
Copyright 2018 Toni de la Fuente

Prowler is a tool that provides automate auditing and hardening guidance of an
AWS account. It is based on AWS-CLI commands. It follows some guidelines
present in the CIS Amazon Web Services Foundations Benchmark at:
https://d0.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf

Contact the author at https://blyx.com/contact
and open issues or ask questions at https://github.com/toniblyx/prowler


All CIS based checks in checks folder are licensed under a Creative Commons
Attribution-NonCommercial-ShareAlike 4.0 International Public License.
The link to the license terms can be found at
https://creativecommons.org/licenses/by-nc-sa/4.0/legalcode
#
Any other piece of code is licensed as Apache License 2.0 as specified in
each file. You may obtain a copy of the License at
http://www.apache.org/licenses/LICENSE-2.0

Prowler - Iron Maiden
#
Walking through the city, looking oh so pretty
I've just got to find my way
See the ladies flashing
All there legs and lashes
I've just got to find my way...
""")
parser.add_argument('-p', '--profile', help='specify your AWS profile to use (i.e.: default)')
parser.add_argument('-r', '--region', default='us-east-1', help='specify an AWS region to direct API requests to (i.e.: us-east-1), all regions are checked anyway if the check requires it')
parser.add_argument('-c', '--check', help='specify one or multiple check ids separated by commas, to see all available checks use "-l" option (i.e.: "check11" for check 1.1 or "extra71,extra72" for extra check 71 and extra check 72)')
parser.add_argument('-g', '--group', help='specify a group of checks by id, to see all available group of checks use "-L" (i.e.: "check3" for entire section 3, "level1" for CIS Level 1 Profile Definitions or "forensics-ready")')
parser.add_argument('-f', '--filter-region', help='specify an AWS region to run checks against (i.e.: us-west-1)')
parser.add_argument('-m', '--maxitems', help='specify the maximum number of items to return for long-running requests (default: 100)')
parser.add_argument('-M', '--mode', default='text', help='output mode: text (default), mono, json, csv (separator is ","; data is on stdout; progress on stderr)')
parser.add_argument('-k', '--keep-credential-report', action='store_true', help='keep the credential report')
parser.add_argument('-n', '--numbers', action='store_true', help='show check numbers to sort easier (i.e.: 1.01 instead of 1.1)')
parser.add_argument('-l', '--list', action='store_true', help='list all available checks only (does not perform any check)')
parser.add_argument('-L', '--list-groups', action='store_true', help='list all groups (does not perform any check)')
parser.add_argument('-e', '--exclude-extras', help='exclude group extras')
parser.add_argument('-E', '--all-except', help='execute all tests except a list of specified checks separated by comma (i.e. check21,check31)')
parser.add_argument('-b', '--no-banner', action='store_true', help='do not print Prowler banner')
parser.add_argument('-V', '--version', action='store_true', help='show version number & exit')

args = parser.parse_args()

# prepare environment that we'll run checks in
# set MODE to "json" regardless of how we were called, so we can
# reliably parse the result
env = dict(os.environ)
env['MODE'] = 'json'
env['AWSCLI'] = find_awscli()
env['TEMP_REPORT_FILE'] = credential_report_temp_file

checks = read_check_files()
groups = read_group_files()

profile_opt = ''

def prowlerBanner():
    print(Fore.CYAN + "                          _", file=sys.stderr)
    print("  _ __  _ __ _____      _| | ___ _ __", file=sys.stderr)
    print(" | '_ \| '__/ _ \ \ /\ / / |/ _ \ '__|", file=sys.stderr)
    print(" | |_) | | | (_) \ V  V /| |  __/ |", file=sys.stderr)
    print(' | .__/|_|  \___/ \_/\_/ |_|\___|_|v'+VERSION, file=sys.stderr)
    print(' |_|'+Fore.BLUE+' the handy cloud security tool'+Style.RESET_ALL, file=sys.stderr)
    print(Fore.YELLOW+" Date: " + datetime.now().strftime('%c'), file=sys.stderr)
    printColorsCode

def printColorsCode():
    print(Style.RESET_ALL + ' Colors code for results: ', file=sys.stderr)
    print(Fore.YELLOW+' INFO (Information)'+Style.RESET_ALL+','+Fore.GREEN+' PASS (Recommended value), '+Fore.RED+' FAIL (Fix required)'+Style.RESET_ALL+','+Fore.MAGENTA+" Not Scored "+Style.RESET_ALL, file=sys.stderr)

prowlerBanner()
printColorsCode()

if args.profile:
    profile_opt = '--profile=' + args.profile

if args.list:
    checks_sorted = sorted(checks.values(), key = lambda x: x['id'])

    for c in checks_sorted:
        print(c['id'], c['title'])

elif args.list_groups:
    groups_sorted = sorted(groups.values(), key = lambda x: x['id'])

    for g in groups_sorted:
        print(g['id'], g['title'])

elif args.check:
    result = []
    for check in args.check.split(','):
        result.extend(execute_check(check))

    if args.mode == 'json':
        print(simplejson.dumps(result))

    elif args.mode == 'csv':
        for r in result:
            print("%s,%s,%s,%s,%s,%s,%s,%s,%s" % (
                r['Profile'],
                r['Account Number'],
                r['Region'],
                r['Control ID'],
                r['Status'].upper(),
                r['Scored'],
                r['Level'],
                r['Control'],
                r['Message'],
            ))

    elif args.mode == 'text':
        for r in result:
            status_text = ''

            if r['Status'].upper() == 'FAIL':
                status_text = "      " + Fore.RED + " FAIL! " + r['Control'] + Style.RESET_ALL
            elif r['Status'].upper() == 'PASS':
                status_text = "      " + Fore.GREEN + " PASS! " + r['Control'] + Style.RESET_ALL

            if r['Scored'] in [ 'Yes', '1', 'SCORED' ]:
                print(Fore.BLUE + ' ' + r['Control ID'] + Style.RESET_ALL + ' ' + r['Control'], file=sys.stderr)
            else:
                print(Fore.MAGENTA + ' ' + r['Control ID'] + Style.RESET_ALL + ' ' + r['Control'], file=sys.stderr)
    
    else:
        raise ValueError('unknown mode ' + args.mode)

if not args.keep_credential_report:
    os.unlink(credential_report_temp_file)
