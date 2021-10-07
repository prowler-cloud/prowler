#!/usr/bin/python
import signal
import sys
import argparse
import subprocess
import json
from datetime import datetime
import os
import re
from socket import socket, AF_UNIX, SOCK_DGRAM


################################################################################
# Constants
################################################################################
DEBUG = 0
WAZUH_PATH = '/var/ossec'
WAZUH_QUEUE = '/var/ossec/queue/sockets/queue'
DEBUG_LEVEL = 0  # Enable/disable debug mode
PATH_TO_PROWLER ='/var/ossec/integrations/prowler'
ACCOUNT_FILE='/var/ossec/integrations/prowler/account.lst'
TEMPLATE_CHECK = '''
{{
  "integration": "prowler",
  "prowler": {0}
}}
'''
TEMPLATE_MSG = '1:Wazuh-Prowler:{0}'
TEMPLATE_ERROR = '''{{
  "aws_account_id": {aws_account_id},
  "aws_profile": "{aws_profile}",
  "prowler_error": "{prowler_error}",
  "prowler_version": "{prowler_version}",
  "timestamp": "{timestamp}",
  "status": "Error"
}}
'''
FIELD_REMAP = {
  "Profile": "aws_profile",
  "Control": "control",
  "Account Number": "aws_account_id",
  "Level": "level",
  "Account Alias": "aws_account_alias",
  "Timestamp": "timestamp",
  "Region": "region",
  "Control ID": "control_id",
  "Service": "service",
  "Status": "status",
  "Scored": "scored",
  "Message": "message",
  "Compliance": "Compliance",
  "remediation": "remediation",
  "Resource ID": "resource_id",
  "Doc Link": "doc_link",
  "CAF Epic": "caf_epic",
  "risk": "risk"

}
CHECKS_FILES_TO_IGNORE = [
  'check_sample'
]

#functions
def read_account():
    with open(ACCOUNT_FILE,'r') as file:
        lines=file.readlines()
        acc=[line.strip() for line in lines]
        return acc

def _send_msg(msg):
  try:
    _json_msg = json.dumps(_reformat_msg(msg))
    _debug("Sending Msg: {0}".format(_json_msg), 3)
    wsock = socket(AF_UNIX, SOCK_DGRAM)
    wsock.connect(WAZUH_QUEUE)
    wsock.send(TEMPLATE_MSG.format(_json_msg).encode())
    wsock.close()
  except Exception as e:
        print("ERROR: Error sending message to wazuh: {}".format(e))
        sys.exit(6)
  return

def _handler(signal, frame):
  print("ERROR: SIGINT received.")
  sys.exit(12)

def _get_script_arguments():
  _parser = argparse.ArgumentParser(usage="usage: %(prog)s [options]",
                                    description="Wazuh wodle for evaluating AWS security configuration",
                                    formatter_class=argparse.RawTextHelpFormatter)
  _parser.add_argument('-R', '--role', help='You need to specify the role' ,dest='role', default=None,required=True)
  _parser.add_argument('-f', '--zone', help='You need to specify the zone you need to scan. Due to support multiples accounts, just one zone once',dest='zone', default='All',required=True)
  _parser.add_argument('-d', '--debug', action='store', dest='debug', default=0, help='Enable debug')
  _parser.add_argument('-p', '--aws_profile', dest='aws_profile', help='The name of credential profile to use',
                       default=None)
  _parser.add_argument('-n', '--aws_account_alias', dest='aws_account_alias',
                       help='AWS Account ID Alias', default='')
  _parser.add_argument('-e', '--skip_on_error', action='store_false', dest='skip_on_error',
                       help='If check output is invalid json, error out instead of skipping the check', default=True)
  return _parser.parse_args()


def _debug(msg, msg_level):
  if DEBUG_LEVEL >= msg_level:
    print('DEBUG-{level}: {debug_msg}'.format(level=msg_level, debug_msg=msg))

def _run_prowler(prowler_args):
    _prowler_command = '{prowler}/prowler {args}'.format(prowler=PATH_TO_PROWLER,args=prowler_args)
    _debug('Running command: {0}'.format(_prowler_command), 2)
    _process = subprocess.Popen(_prowler_command, stdout=subprocess.PIPE, shell=True)
    _output, _error = _process.communicate()
    _debug('Raw prowler output: {0}'.format(_output), 3)
    if _error is not None:
        _debug('PROWLER ERROR: {0}'.format(_error), 1)
        exit(3)
    return _output

def _get_prowler_version():
  _debug('+++ Get Prowler Version', 1)
  # Execute prowler, but only display the version and immediately exit
  _version=subprocess.Popen('{prowler}/prowler -b -V'.format(prowler=PATH_TO_PROWLER), stdout=subprocess.PIPE, shell=True)
  _output, _error = _version.communicate()
  return _output.format().rstrip()

def _get_prowler_results(prowler_check,account,options):
  _debug('+++ Get Prowler Results '.format(), 1)
  return _run_prowler('-M wazuh -b -c {check} -A {account} -R {role} -f {zone}'.format(check=prowler_check,account=account,role=options.role,zone=options.zone))


def _get_prowler_checks():
  _prowler_checks = []
  for _directory_path, _directories, _files in os.walk('{path}/checks'.format(path=PATH_TO_PROWLER)):
    _debug('Checking in : {}'.format(_directory_path), 3)
    for _file in _files:
      if _file in CHECKS_FILES_TO_IGNORE:
        _debug('Ignoring check - {}'.format(_directory_path, _file), 3)
      elif re.match("check\d+", _file):
        _prowler_checks.append(_file)
      elif re.match("check_extra(\d+)", _file):
        _prowler_checks.append(_file[6:])
      else:
        _debug('Unknown check file type- {}'.format(_directory_path, _file), 3)
  return _prowler_checks


def _send_prowler_results(prowler_results, _prowler_version,options):
  _debug('+++ Send Prowler Results', 1)
  for _check_result in prowler_results.splitlines():
    # Empty row
    if len(_check_result) < 1:
      continue
    # Something failed during prowler check
    elif _check_result[:17] == 'An error occurred':
      _debug('ERROR MSG --- {0}'.format(_check_result), 2)
      _temp_msg = TEMPLATE_ERROR.format(
        aws_account_id="1",
        aws_profile="default",
        role = options.role,
        zone = options.zone,
        prowler_error="error",
        prowler_version=_prowler_version,
        timestamp=datetime.now().isoformat()
      )
      _error_msg = json.loads(TEMPLATE_CHECK.format(_temp_msg))
      _send_msg(_error_msg)
      continue
    try:
      _debug('RESULT MSG --- {0}'.format(_check_result), 2)
      _check_result = json.loads(TEMPLATE_CHECK.format(_check_result))
    except:
      _debug('INVALID JSON --- {0}'.format(TEMPLATE_CHECK.format(_check_result)), 1)
      if not options.skip_on_error:
          exit(4)
    _check_result['prowler']['prowler_version'] = _prowler_version
    print(_check_result)
    _send_msg(_check_result)

  return True


def _reformat_msg(msg):
  for field in FIELD_REMAP:
    if field in msg['prowler']:
      msg['prowler'][FIELD_REMAP[field]] = msg['prowler'][field]
      del msg['prowler'][field]
  return msg

# Main
###############################################################################
def main(argv):
  _debug('+++ Begin script', 1)
  # Parse arguments
  _options = _get_script_arguments()
  if int(_options.debug) > 0:
    global DEBUG_LEVEL
    DEBUG_LEVEL = int(_options.debug)
    _debug('+++ Debug mode on - Level: {debug}'.format(debug=_options.debug), 1)


  _prowler_version = _get_prowler_version()
  _prowler_checks = _get_prowler_checks()
  acc = read_account()
  for account in acc:
      for _check in _prowler_checks:
          _prowler_results = _get_prowler_results(_check,account,_options)
          _send_prowler_results(_prowler_results, _prowler_version,_options)
  _debug('+++ Finished script', 1)
  return


if __name__ == '__main__':
  try:
    _debug('Args: {args}'.format(args=str(sys.argv)), 2)
    signal.signal(signal.SIGINT, _handler)
    main(sys.argv[1:])
    sys.exit(0)
  except Exception as e:
    print("Unknown error: {}".format(e))
    if DEBUG_LEVEL > 0:
      raise
    sys.exit(1)
