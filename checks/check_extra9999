#!/usr/bin/env bash

# Prowler - the handy cloud security tool (copyright 2019) by Toni de la Fuente
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may not
# use this file except in compliance with the License. You may obtain a copy
# of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed
# under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, either express or implied. See the License for the
# specific language governing permissions and limitations under the License.

CHECK_ID_extra9999="9.9999"
CHECK_TITLE_extra9999="[check9999] Custom Defined Check"
CHECK_SCORED_extra79999="NOT_SCORED"
CHECK_CIS_LEVEL_extra9999="EXTRA"
CHECK_SEVERITY_extra9999="Critical"
CHECK_ASFF_RESOURCE_TYPE_extra9999="Custom"
CHECK_ALTERNATE_extra9999="extra9999"
CHECK_SERVICENAME_extra9999="custom"
CHECK_RISK_cextra9999="Custom Defined Risk"
CHECK_REMEDIATION_extra9999="Custom Remediation"
CHECK_CAF_EPIC_extra9999="Custom EPIC"

extra9999(){

    for regx in $REGIONS; do
        MY_CUSTOM_CMD=$($AWSCLI $CUSTOM_CMD $PROFILE_OPT --region $regx --output text 2>&1)
        if [[ $(echo "$MY_CUSTOM_CMD" | grep -E 'AccessDenied|UnauthorizedOperation') ]]; then
            textInfo "$regx: Access Denied or error trying to execute the custom command" "$regx"
            continue
        fi
        if [[ $MY_CUSTOM_CMD ]]; then
            for element in $MY_CUSTOM_CMD; do 
                textFail "$regx: Custom output is: $element" "$regx" "$CHECK_SGDEFAULT_ID"
            done
        else
            textPass "$regx: Custom output is empty" "$regx" "$CHECK_SGDEFAULT_ID"
        fi
    done
}
