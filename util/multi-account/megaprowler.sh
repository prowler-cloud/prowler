#!/bin/bash

BASEDIR=$(dirname "${0}")
# source the configuration data from "config" in this directory
if [[ -f "${BASEDIR}/config" ]]; then
  # shellcheck disable=SC1090
  . "${BASEDIR}/config"

else
  echo "CONFIG file missing - ${BASEDIR}/config"
  exit 255
fi

## Check Environment variables which are set by config
if [[ "${ORG_MASTERS}X" == "X" && "${STANDALONE_ACCOUNTS}X" == "X" ]]; then
  echo "No audit targets specified. Failing."
  exit 15
fi
if [[ -z $SKIP_ACCOUNTS_REGEX ]]; then
  SKIP_ACCOUNTS_REGEX=""
fi

if [[ -z $CHECKGROUP ]]; then
  echo "Missing check group from config file"
  exit 255
fi
if [[ -z $AUDIT_ROLE ]]; then
  echo "Missing audit role from config file"
  exit 255
fi

## ========================================================================================

## Check Arguments
if [ $# -lt 1 ]; then
  echo "NEED AN OUTPUT DIRECTORY"
  exit 2
else
  if [[ -d $1 && -w $1 ]]; then
    OUTBASE=$1
  else
    echo "Output directory missing or write-protected"
    exit 1
  fi
fi


## Check Requirements
if [[ -x $(command -v aws) ]]; then
  aws --version
else
  echo "AWS CLI is not in PATH ... giving up"
  exit 4
fi

if [[ -x $(command -v jq) ]]; then
  jq --version
else
  echo "JQ is not in PATH ... giving up"
  exit 4
fi

# Ensure AWS Credentials are present in environment
if [[ -z $CREDSOURCE ]]; then
  echo "No source for base credentials ... giving up"
  exit 5
fi

if [[ -f ${PROWLER} && -x ${PROWLER} ]]; then
  ${PROWLER} -V
else
  echo "Unable to execute prowler from ${PROWLER}"
  exit 3
fi


## Preflight checks complete

DAYPATH=$(date -u +%Y/%m/%d)
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
## Create output subdirs
OUTDATA="${OUTBASE}/data/${DAYPATH}"
OUTLOGS="${OUTBASE}/logs/${DAYPATH}"
mkdir -p "${OUTDATA}" "${OUTLOGS}"


if [[ -x $(command -v parallel) ]]; then
  # Note: the "standard" codebuild container includes parallel
  echo "Using GNU sem/parallel, with NCPU+4 jobs"
  parallel --citation > /dev/null 2> /dev/null
  PARALLEL_START="parallel --semaphore --fg --id p_${STAMP} --jobs +4 --env AWS_SHARED_CREDENTIALS_FILE"
  PARALLEL_START_SUFFIX=''
  PARALLEL_END="parallel --semaphore --wait --id p_${STAMP}"
else
  echo "Consider installing GNU Parallel to avoid punishing your system"
  PARALLEL_START=''
  PARALLEL_START_SUFFIX=' &'
  # shellcheck disable=SC2089
  PARALLEL_END="echo 'WAITING BLINDLY FOR PROCESSES TO COMPLETE'; wait ; sleep 30 ; wait"
fi

echo "Execution Timestamp: ${STAMP}"

ALL_ACCOUNTS=""


# Create a temporary credential file
AWS_MASTERS_CREDENTIALS_FILE=$(mktemp -t prowler.masters-XXXXXX)
echo "Preparing Credentials ${AWS_MASTERS_CREDENTIALS_FILE} ( ${CREDSOURCE} )"
echo "# Master Credentials ${STAMP}"   >> "${AWS_MASTERS_CREDENTIALS_FILE}"
echo ""                                >> "${AWS_MASTERS_CREDENTIALS_FILE}"

AWS_TARGETS_CREDENTIALS_FILE=$(mktemp -t prowler.targets-XXXXXX)
echo "Preparing Credentials ${AWS_TARGETS_CREDENTIALS_FILE} ( ${CREDSOURCE} )"
echo "# Target Credentials ${STAMP}" >> "${AWS_TARGETS_CREDENTIALS_FILE}"
echo ""                              >> "${AWS_TARGETS_CREDENTIALS_FILE}"


## Visit the Organization Master accounts & build a list of all member accounts
export AWS_SHARED_CREDENTIALS_FILE=$AWS_MASTERS_CREDENTIALS_FILE
for org in $ORG_MASTERS ; do
  echo -n "Preparing organization $org "
  # create credential profile
  {
  echo "[audit_${org}]"
  echo "role_arn = arn:aws:iam::${org}:role${AUDIT_ROLE}"
  echo "credential_source = ${CREDSOURCE}"
  echo ""
  } >> "${AWS_MASTERS_CREDENTIALS_FILE}"

  # Get the Organization ID to use for output paths, collecting info, etc
  org_id=$(aws --output json --profile "audit_${org}" organizations describe-organization | jq -r '.Organization.Id' )

  echo "( $org_id )"
  ORG_ID_LIST="${ORG_ID_LIST} ${org_id}"


  # Build the list of all accounts in the organizations
  aws --output json --profile "audit_${org}" organizations list-accounts > "${OUTLOGS}/${STAMP}-${org_id}-account-list.json"
  # shellcheck disable=SC2002
  ORG_ACCOUNTS=$( cat "${OUTLOGS}/${STAMP}-${org_id}-account-list.json" | jq -r '.Accounts[].Id' | tr "\n" " ")
  ALL_ACCOUNTS="${ALL_ACCOUNTS} ${ORG_ACCOUNTS}"

  # Add the Org's Accounts (including master) to the TARGETS_CREDENTIALS file
  for target in $ORG_ACCOUNTS ; do
    if echo "$target" | grep -qE "${SKIP_ACCOUNTS_REGEX}"; then
      echo " skipping account      ${target} ( ${org_id} )"
      continue
    fi
    # echo "  ${org_id}_${target}"
    {
    echo "[${org_id}_${target}]"
    echo "role_arn = arn:aws:iam::${target}:role${AUDIT_ROLE}"
    echo "credential_source = ${CREDSOURCE}"
    echo ""
    } >> "${AWS_TARGETS_CREDENTIALS_FILE}"
  done

done

# Prepare credentials for standalone accounts
if [[ "" != "${STANDALONE_ACCOUNTS}" ]] ; then
  # mkdir -p ${OUTBASE}/data/standalone/${DAYPATH} ${OUTBASE}/logs/standalone/${DAYPATH}
  for target in $STANDALONE_ACCOUNTS ; do
    echo "Preparing account      ${target} ( standalone )"
    {
    echo "[standalone_${target}]"
    echo "role_arn = arn:aws:iam::${target}:role${AUDIT_ROLE}"
    echo "credential_source = ${CREDSOURCE}"
    echo ""
    } >> "${AWS_TARGETS_CREDENTIALS_FILE}"
  done
  ALL_ACCOUNTS="${ALL_ACCOUNTS} ${STANDALONE_ACCOUNTS}"
fi

# grep -E '^\[' $AWS_MASTERS_CREDENTIALS_FILE $AWS_TARGETS_CREDENTIALS_FILE


# Switch to Target Credential Set
export AWS_SHARED_CREDENTIALS_FILE=${AWS_TARGETS_CREDENTIALS_FILE}

## visit each target account
NUM_ACCOUNTS=$(grep -cE '^\[' "${AWS_TARGETS_CREDENTIALS_FILE}")
echo "Launching ${CHECKGROUP} audit of ${NUM_ACCOUNTS} accounts"
for member in $(grep -E '^\[' "${AWS_TARGETS_CREDENTIALS_FILE}" | tr -d '][') ; do
  ORG_ID=$(echo "$member" | cut -d'_' -f1)
  ACCOUNT_NUM=$(echo "$member" | cut -d'_' -f2)

  # shellcheck disable=SC2086
  ${PARALLEL_START} "${PROWLER} -p ${member} -n -M csv -g ${CHECKGROUP} 2> ${OUTLOGS}/${STAMP}-${ORG_ID}-${ACCOUNT_NUM}-prowler-${CHECKGROUP}.log  > ${OUTDATA}/${STAMP}-${ORG_ID}-${ACCOUNT_NUM}-prowler-${CHECKGROUP}.csv ; echo \"${ORG_ID}-${ACCOUNT_NUM}-prowler-${CHECKGROUP} finished\" " ${PARALLEL_START_SUFFIX}
done

echo -n "waiting for parallel threads to complete - " ; date
# shellcheck disable=SC2090
${PARALLEL_END}

echo "Completed ${CHECKGROUP} audit with stamp ${STAMP}"

# mkdir -p ${OUTBASE}/logs/debug/${DAYPATH}
# cp "$AWS_MASTERS_CREDENTIALS_FILE" "${OUTLOGS}/${STAMP}-master_creds.txt"
# cp "$AWS_TARGETS_CREDENTIALS_FILE" "${OUTLOGS}/${STAMP}-target_creds.txt"
rm "$AWS_MASTERS_CREDENTIALS_FILE" "$AWS_TARGETS_CREDENTIALS_FILE"
