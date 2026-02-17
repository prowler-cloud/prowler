import base64
import logging
import os
import re
import sys

import oci

# Logging config
logging.basicConfig(
    stream=sys.stdout,
    format="%(asctime)s [File: %(filename)s:%(lineno)d] \t[Module: %(module)s]\t %(levelname)s: %(message)s",
    datefmt="%m/%d/%Y %I:%M:%S %p",
    level=logging.INFO,
)

# OCI regions are fetched dynamically from the Identity API
# No hardcoded display names - following AWS regions updater pattern
# This ensures full automation without manual maintenance


def setup_oci_client():
    """
    Set up OCI Identity client using credentials from environment variables.

    Returns:
        oci.identity.IdentityClient: Authenticated OCI Identity client

    Raises:
        ValueError: If required environment variables are missing
        Exception: If authentication fails
    """
    logging.info("Setting up OCI client authentication")

    # Validate required environment variables
    required_vars = [
        "OCI_CLI_USER",
        "OCI_CLI_FINGERPRINT",
        "OCI_CLI_TENANCY",
        "OCI_CLI_KEY_CONTENT",
    ]

    missing_vars = [var for var in required_vars if not os.getenv(var)]
    if missing_vars:
        raise ValueError(
            f"Missing required environment variables: {', '.join(missing_vars)}"
        )

    # Get credentials from environment
    user_ocid = os.getenv("OCI_CLI_USER")
    fingerprint = os.getenv("OCI_CLI_FINGERPRINT")
    tenancy_ocid = os.getenv("OCI_CLI_TENANCY")
    key_content_raw = os.getenv("OCI_CLI_KEY_CONTENT")
    region = os.getenv("OCI_CLI_REGION", "us-ashburn-1")

    # Decode private key: the secret is stored base64-encoded (same format
    # the UI/API use). If it's already raw PEM, use it directly.
    if key_content_raw.strip().startswith("-----BEGIN"):
        key_content = key_content_raw
    else:
        try:
            key_content = base64.b64decode(key_content_raw).decode("utf-8")
        except Exception as e:
            raise ValueError(f"Failed to decode OCI_CLI_KEY_CONTENT: {e}")

    # Create OCI config dictionary
    config = {
        "user": user_ocid,
        "fingerprint": fingerprint,
        "tenancy": tenancy_ocid,
        "key_content": key_content,
        "region": region,
    }

    # Initialize Identity client
    try:
        identity_client = oci.identity.IdentityClient(config)
        logging.info(f"Successfully authenticated to OCI region: {region}")
        return identity_client
    except Exception as e:
        raise Exception(f"Failed to create OCI Identity client: {e}")


def fetch_oci_regions(identity_client):
    """
    Fetch all OCI commercial regions using the Identity service API.

    Args:
        identity_client (oci.identity.IdentityClient): Authenticated OCI client

    Returns:
        dict: Dictionary mapping region identifiers to themselves (for consistency)

    Raises:
        Exception: If API call fails
    """
    logging.info("Fetching OCI commercial regions from Identity service")

    try:
        # Call list_regions() API - returns all OC1 commercial regions
        response = identity_client.list_regions()
        regions = response.data

        logging.info(f"Successfully fetched {len(regions)} regions from OCI API")

        # Build region dictionary (region_id -> region_id)
        # Following AWS pattern: no display names, fully automated
        region_dict = {}
        for region in regions:
            region_id = region.name
            region_dict[region_id] = region_id
            logging.debug(f"Added region: {region_id}")

        # Sort regions alphabetically by key
        region_dict = dict(sorted(region_dict.items()))

        logging.info(f"Processed {len(region_dict)} commercial regions")
        return region_dict

    except Exception as e:
        raise Exception(f"Failed to fetch OCI regions: {e}")


def update_config_file(regions, config_file_path):
    """
    Update the OCI config file with new commercial regions while preserving government regions.

    Args:
        regions (dict): Dictionary of region identifiers to region identifiers
        config_file_path (str): Path to the config.py file

    Raises:
        Exception: If file operations fail or validation fails
    """
    logging.info(f"Updating config file: {config_file_path}")

    # Read current config file
    try:
        with open(config_file_path, "r") as f:
            config_content = f.read()
    except Exception as e:
        raise Exception(f"Failed to read config file: {e}")

    # Generate new OCI_COMMERCIAL_REGIONS dictionary
    new_regions_dict = "OCI_COMMERCIAL_REGIONS = {\n"
    for region_id in regions.keys():
        new_regions_dict += f'    "{region_id}": "{region_id}",\n'
    new_regions_dict += "}"

    # Replace OCI_COMMERCIAL_REGIONS using regex
    pattern = r"OCI_COMMERCIAL_REGIONS\s*=\s*\{[^}]*\}"
    updated_content = re.sub(pattern, new_regions_dict, config_content)

    # Validate that government regions still exist
    if "OCI_GOVERNMENT_REGIONS" not in updated_content:
        raise Exception(
            "Validation failed: OCI_GOVERNMENT_REGIONS section missing after update. Aborting to prevent data loss."
        )

    # Verify the replacement was successful
    if updated_content == config_content:
        logging.warning("No changes detected in config file")
        return

    # Write updated content back to file
    try:
        with open(config_file_path, "w") as f:
            f.write(updated_content)
        logging.info("Successfully updated config file")
    except Exception as e:
        raise Exception(f"Failed to write updated config file: {e}")

    # Log summary of changes
    logging.info(f"Updated OCI_COMMERCIAL_REGIONS with {len(regions)} regions")


def main():
    """
    Main execution function for OCI regions updater.
    """
    try:
        # Setup OCI client with authentication
        identity_client = setup_oci_client()

        # Fetch all commercial regions from OCI API
        commercial_regions = fetch_oci_regions(identity_client)

        # Update config.py file
        config_file_path = os.path.join(
            os.path.dirname(os.path.realpath(__file__)),
            "..",
            "prowler",
            "providers",
            "oraclecloud",
            "config.py",
        )

        update_config_file(commercial_regions, config_file_path)

        logging.info("OCI regions update completed successfully")
        return 0

    except Exception as e:
        logging.error(f"Error during OCI regions update: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
