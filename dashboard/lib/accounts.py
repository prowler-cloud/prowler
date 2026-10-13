import glob
import os

import pandas as pd

from prowler.lib.logger import logger


def is_valid_account_name(name) -> bool:
    """Return True when the account name is a usable, non-empty string."""
    if not isinstance(name, str):
        return False
    name = name.strip()
    return bool(name) and name.lower() != "nan"


def build_aws_account_names(data: pd.DataFrame) -> dict:
    """
    Build an ACCOUNT_UID -> ACCOUNT_NAME map for the AWS rows of a findings DataFrame.
    Args:
        data (pd.DataFrame): Findings data with PROVIDER, ACCOUNT_UID and ACCOUNT_NAME columns.
    Returns:
        dict: AWS account IDs mapped to their account name. Accounts without a name are left out.
    """
    if data is None or not {"PROVIDER", "ACCOUNT_UID", "ACCOUNT_NAME"}.issubset(
        data.columns
    ):
        return {}
    aws_rows = data[data["PROVIDER"] == "aws"]
    account_names = {}
    for account_uid, account_name in zip(
        aws_rows["ACCOUNT_UID"], aws_rows["ACCOUNT_NAME"]
    ):
        if is_valid_account_name(account_name):
            account_names[str(account_uid)] = account_name.strip()
    return account_names


def load_aws_account_names(folder_path: str) -> dict:
    """
    Read the AWS account names from the findings CSV files in a folder.
    Args:
        folder_path (str): Folder containing the findings CSV files.
    Returns:
        dict: AWS account IDs mapped to their account name.
    """
    account_names = {}
    columns = {"PROVIDER", "ACCOUNT_UID", "ACCOUNT_NAME"}
    for file in glob.glob(os.path.join(folder_path, "*.csv")):
        try:
            df = pd.read_csv(
                file,
                sep=";",
                on_bad_lines="skip",
                usecols=lambda column: column in columns,
                dtype=str,
            )
        except Exception:
            logger.error(f"Error reading file {file}")
            continue
        account_names.update(build_aws_account_names(df))
    return account_names


def format_aws_account_label(account_uid: str, account_names: dict) -> str:
    """
    Return the display label for an AWS account: "<name> (<id>)", or "<id>" without a name.
    """
    account_name = account_names.get(account_uid)
    if account_name:
        return f"{account_name} ({account_uid})"
    return account_uid
