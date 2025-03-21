# Test the OpenNebulaProvider class
import os
import sys
import logging
from prowler.providers.opennebula.opennebula_provider import OpenNebulaProvider
from prowler.providers.opennebula.exceptions.exceptions import OpenNebulaError

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def test_opennebula_provider(credentials_file: str = None) -> bool:
    """Test the OpenNebulaProvider class."""
    logger.info("Starting OpenNebulaProvider test")
    
    try:
        provider = OpenNebulaProvider(credentials_file)
        # Print credentials using the class method
        provider.print_credentials()
        return True
    
    except OpenNebulaError as e:
        logger.error(f"OpenNebula API Error: {e}")
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