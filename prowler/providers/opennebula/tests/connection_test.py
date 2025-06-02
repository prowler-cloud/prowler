# Test the OpennebulaProvider class
import os
import sys
import logging
from prowler.providers.opennebula.opennebula_provider import OpennebulaProvider
from prowler.providers.opennebula.exceptions.exceptions import OpennebulaError

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def test_opennebula_provider(credentials_file: str = None) -> bool:
    """Test the OpennebulaProvider class."""
    logger.info("Starting OpennebulaProvider test")
    
    try:
        provider = OpennebulaProvider(credentials_file)
        # Print credentials using the class method
        provider.print_credentials()
        return True
    
    except OpennebulaError as e:
        logger.error(f"Opennebula API Error: {e}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        return False

if __name__ == "__main__":
    credentials_file   =  "/home/dani/TFM_prowler/prowler/providers/opennebula/tests/.env.test"
    result = test_opennebula_provider(credentials_file)
    if result:
        logger.info("Test completed successfully")
        sys.exit(0)
    else:
        logger.error("Test failed")
        sys.exit(1)