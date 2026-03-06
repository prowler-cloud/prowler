# prowler/contrib/aws/simulate_policy_service.py

import json
import logging
from typing import Dict, List, Optional, Tuple

from botocore.exceptions import ClientError

from prowler.providers.common.provider import Provider

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


# ======================================================================
# PURPOSE
# ----------------------------------------------------------------------
# This module provides a precise way to test IAM actions programmatically.
# It replicates the behaviour of the AWS CLI command:
#   aws iam simulate-principal-policy --policy-source-arn arn:aws:iam::<account>:role/<role> --action-names <action>
#
# Use this when you need to validate whether a specific IAM role allows or denies
# certain actions against given resources.
#
# ======================================================================
# CLI ANALOGUE
# ----------------------------------------------------------------------
# Example equivalent CLI command:
#   aws iam simulate-principal-policy \
#       --policy-source-arn arn:aws:iam::278419598935:role/your-role \
#       --action-names datazone:AcceptPredictions
#
# ======================================================================
# DOCUMENTATION
# ----------------------------------------------------------------------
# AWS IAM Policy Simulator:
#   https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_testing-policies.html
#
# IAM Condition Keys:
#   https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html
#
# Related AWS SDK discussion:
#   https://github.com/aws/aws-sdk/issues/102
#
# ======================================================================
# LIMITATIONS
# ----------------------------------------------------------------------
# - The IAM Policy Simulator does NOT evaluate Service Control Policies (SCPs)
#   that include conditions. This is a limitation of the API.
# - In environments where SCPs contain conditions, use
#   `is_action_allowed_simulate_custom_policy` instead.
# - In environments without SCP conditions, `is_action_allowed_simulate_principal_policy`
#   works as expected.
#
# ======================================================================
# USAGE
# ----------------------------------------------------------------------
# In your custom check:
#
#   from prowler.contrib.aws.simulate_policy.simulate_policy_client import get_iam_simulator_client
#
#   iam_sim = get_iam_simulator_client()
#   policy_data = iam_sim.get_role_policy_data(role_name=role_name)
#   iam_sim.is_action_allowed_simulate_custom_policy(
#       policy_data=policy_data,
#       action_names=[action],
#       resource_arns=["*"]
#   )
#
#
# ======================================================================


class IamSimulator:
    """
    Helper for IAM Policy Simulator:
      - simulate_principal_policy
      - simulate_custom_policy
      - collect role inline/managed policies
    """

    def __init__(self, provider: Provider) -> None:

        boto3_session = provider.session.current_session

        # IAM is a global service. Region is optional; we can use the provider's global region
        # to stay consistent across partitions.
        try:
            region_name = provider.get_global_region()
        except AttributeError:
            # Fallback if provider lacks the helper (older trees)
            region_name = boto3_session.region_name or "us-east-1"

        self.iam = boto3_session.client("iam", region_name=region_name)

    def is_action_allowed_simulate_principal_policy(
        self,
        principal_arn: str,
        action_names: List[str],
        resource_arns: Optional[List[str]] = None,
    ) -> Tuple[bool, Dict]:
        if resource_arns is None:
            resource_arns = ["*"]
        try:
            resp = self.iam.simulate_principal_policy(
                PolicySourceArn=principal_arn,
                ActionNames=action_names,
                ResourceArns=resource_arns,
            )
            allowed = any(
                r.get("EvalDecision") == "allowed"
                for r in resp.get("EvaluationResults", [])
            )
            return allowed, resp
        except ClientError as e:
            logger.error("simulate_principal_policy failed: %s", e, exc_info=True)
            return False, {"error": str(e)}

    def get_role_policy_data(self, role_name: str) -> Dict[str, List]:
        inline_names: List[str] = []
        inline_docs: List[Dict] = []
        managed_names: List[str] = []
        managed_docs: List[Dict] = []

        # Inline policies
        inline_resp = self.iam.list_role_policies(RoleName=role_name)
        inline_names = inline_resp.get("PolicyNames", [])
        for pname in inline_names:
            pol_resp = self.iam.get_role_policy(RoleName=role_name, PolicyName=pname)
            inline_docs.append(pol_resp["PolicyDocument"])  # dict

        # Managed policies
        managed_resp = self.iam.list_attached_role_policies(RoleName=role_name)
        for attached in managed_resp.get("AttachedPolicies", []):
            managed_names.append(attached["PolicyName"])
            pol_meta = self.iam.get_policy(PolicyArn=attached["PolicyArn"])["Policy"]
            pol_ver = self.iam.get_policy_version(
                PolicyArn=attached["PolicyArn"], VersionId=pol_meta["DefaultVersionId"]
            )
            managed_docs.append(pol_ver["PolicyVersion"]["Document"])  # dict

        return {
            "inline_policy_names": inline_names,
            "inline_policy_data": inline_docs,
            "managed_policy_names": managed_names,
            "managed_policy_data": managed_docs,
        }

    def is_action_allowed_simulate_custom_policy(
        self,
        policy_data: Dict[str, List],
        action_names: List[str],
        resource_arns: Optional[List[str]] = None,
    ) -> Tuple[bool, Dict]:
        names = policy_data.get("inline_policy_names", []) + policy_data.get(
            "managed_policy_names", []
        )
        docs = policy_data.get("inline_policy_data", []) + policy_data.get(
            "managed_policy_data", []
        )

        results: Dict[str, List] = {"policies": []}
        any_allowed = False
        if resource_arns is None:
            resource_arns = ["*"]

        for idx, doc in enumerate(docs):
            name = names[idx] if idx < len(names) else f"policy_{idx}"
            try:
                sim_resp = self.iam.simulate_custom_policy(
                    PolicyInputList=[json.dumps(doc)],
                    ActionNames=action_names,
                    ResourceArns=resource_arns,
                )
            except ClientError as e:
                logger.error(
                    "simulate_custom_policy failed for %s: %s", name, e, exc_info=True
                )
                results["policies"].append({"policy_name": name, "error": str(e)})
                continue

            per_action = []
            for ev in sim_resp.get("EvaluationResults", []):
                decision = ev.get(
                    "EvalDecision"
                )  # allowed | explicitDeny | implicitDeny
                per_action.append(
                    {
                        "action": ev.get("EvalActionName"),
                        "decision": decision,
                        "matching_statements": ev.get("MatchedStatements", []),
                        "missing_context_values": ev.get("MissingContextValues", []),
                    }
                )
                if decision == "allowed":
                    any_allowed = True

            results["policies"].append({"policy_name": name, "evaluations": per_action})

        return any_allowed, results
