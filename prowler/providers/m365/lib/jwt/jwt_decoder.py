import base64
import json
import re


def decode_jwt(token: str) -> dict:
    """
    Decodes the payload of a JWT without verifying its signature.

    Args:
        token (str): JWT string in the format 'header.payload.signature'

    Returns:
        dict: A dictionary containing the decoded payload (claims), or an empty dict on failure.
    """
    try:
        # Split the JWT into its 3 parts
        parts = token.split(".")
        if len(parts) != 3:
            raise ValueError(
                "The token does not have the expected three-part structure."
            )

        # Extract and decode the payload (second part)
        payload_b64 = parts[1]

        # Add padding if necessary for base64 decoding
        padding = "=" * (-len(payload_b64) % 4)
        payload_b64 += padding

        payload_bytes = base64.urlsafe_b64decode(payload_b64)
        payload_json = payload_bytes.decode("utf-8")
        payload = json.loads(payload_json)

        return payload

    except Exception as e:
        print(f"Failed to decode the token: {e}")
        return {}


def decode_msal_token(text: str) -> dict:
    """
    Extracts and decodes the payload of a MSAL token from a given string.

    Args:
        text (str): A string that contains the MSAL token, possibly over multiple lines.

    Returns:
        dict: A dictionary containing the decoded payload (claims), or an empty dict on failure.
    """
    try:
        # Join all lines and remove whitespace
        flattened = "".join(text.split())

        # Search for a valid JWT pattern (three base64url parts separated by dots)
        match = re.search(
            r"([A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+)", flattened
        )
        if not match:
            raise ValueError("No valid JWT found in the input.")

        token = match.group(1)
        return decode_jwt(token)

    except Exception as e:
        print(f"Failed to extract and decode the token: {e}")
        return {}
