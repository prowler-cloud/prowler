#!/usr/bin/env python3
import os
import time
import yaml
import base64
import logging
from pathlib import Path
import requests
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

TOKEN_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/token"
CA_CERT_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
PROWLER_API_URL = os.environ["PROWLER_API_URL"]
K8S_EXTERNAL_HOST = os.environ["K8S_EXTERNAL_HOST"]
PROWLER_USERNAME = os.environ["PROWLER_USERNAME"]
PROWLER_PASSWORD = os.environ["PROWLER_PASSWORD"]
#K8S_HOST = os.environ.get("KUBERNETES_SERVICE_HOST")
#K8S_PORT = os.environ.get("KUBERNETES_SERVICE_PORT")

class TokenFileHandler(FileSystemEventHandler):
    def __init__(self):
        self.last_token = None
        self.prowler_auth_token = self.get_prowler_auth_token()
        # Initial read of the token
        self.check_and_update_token()


    def get_prowler_auth_token(self):

        postData = {
            "data": {
                "type": "tokens",
                "attributes": {
                    "email": f"{PROWLER_USERNAME}",
                    "password": f"{PROWLER_PASSWORD}"
                }
            }
        }

        try:
            response = requests.post(
                f"{PROWLER_API_URL}/api/v1/tokens",
                headers={  'Content-Type': 'application/vnd.api+json',
                            'Accept': 'application/vnd.api+json'},
                json=postData
            )
            response.raise_for_status()
            return response.json()["data"]["attributes"]["access"]
        except Exception as e:
            logger.error(f"Error getting Prowler auth token: {e}")
            raise

    def get_current_token(self):
        return Path(TOKEN_PATH).read_text().strip()

    def get_ca_cert(self):
        return Path(CA_CERT_PATH).read_text()

    def build_kubeconfig(self, token, uid):
        # Read the CA cert
        ca_cert_data = self.get_ca_cert()
        
        # Build the kubeconfig structure
        kubeconfig = {
            "apiVersion": "v1",
            "kind": "Config",
            "current-context": f"{uid}",
            "clusters": [{
                "name": f"{uid}",
                "cluster": {
                    "server": f"{K8S_EXTERNAL_HOST}",
                    "certificate-authority-data": base64.b64encode(ca_cert_data.encode()).decode()
                }
            }],
            "contexts": [{
                "name": f"{uid}",
                "context": {
                    "cluster": f"{uid}",
                    "user": f"{uid}"
                }
            }],
            "users": [{
                "name": f"{uid}",
                "user": {
                    "token": token
                }
            }]
        }
        
        return yaml.dump(kubeconfig)

    def update_prowler_api(self, token):
        try:

            # Check for existing Kubernetes providers
            try:
                response = requests.get(
                    f"{PROWLER_API_URL}/api/v1/providers?filter[provider]=kubernetes",
                    headers={
                        "Authorization": f"Bearer {self.prowler_auth_token}",
                        'Content-Type': 'application/vnd.api+json',
                        'Accept': 'application/vnd.api+json'
                    }
                )
                response.raise_for_status()
                providers_data = response.json()

                if len(providers_data["data"]) > 1:
                    logger.error("More than one Kubernetes provider found. Cannot determine the correct provider to update.")
                    raise Exception("More than one Kubernetes provider found.")
                elif len(providers_data["data"]) == 0:
                    logger.error("No Kubernetes provider found.")
                    raise Exception("No Kubernetes provider found.")
                
                provider = providers_data["data"][0]
                secret_id = provider["relationships"]["secret"]["data"]["id"]
                uid = provider["attributes"]["uid"]
            except Exception as e:
                logger.error(f"Error checking for existing Kubernetes providers: {e}")
                raise
            # Build the kubeconfig file
            kubeconfig = self.build_kubeconfig(token, uid)
            
            response = requests.patch(
                f"{PROWLER_API_URL}/api/v1/providers/secrets/{secret_id}",
                headers={
                    "Authorization": f"Bearer {self.prowler_auth_token}",
                    'Content-Type': 'application/vnd.api+json',
                    'Accept': 'application/vnd.api+json'},
                json={
                    "data": {
                        "type": "provider-secrets",
                        "id": secret_id,
                        "attributes": {
                            "secret": {
                                "kubeconfig_content": kubeconfig
                            },
                            "name": f"Kubernetes service account token - {time.strftime('%Y-%m-%d %H:%M:%S')}"
                        },
                        "relationships": {}
                    }
                }
            )
            response.raise_for_status()
            logger.info("Successfully updated Prowler API with new kubeconfig")
        except Exception as e:
            logger.error(f"Error updating Prowler API: {e}")

    def check_and_update_token(self):
        current_token = self.get_current_token()
        if current_token != self.last_token:
            logger.info("Token changed, updating Prowler API...")
            self.update_prowler_api(current_token)
            self.last_token = current_token

    def on_modified(self, event):
        if event.src_path == TOKEN_PATH:
            self.check_and_update_token()

def main():
    # Verify required environment variables and files
    required_paths = [TOKEN_PATH, CA_CERT_PATH]
    required_env = [PROWLER_API_URL, PROWLER_USERNAME, PROWLER_PASSWORD]
    
    for path in required_paths:
        if not Path(path).exists():
            logger.error(f"Required file not found: {path}")
            raise FileNotFoundError(f"Required file not found: {path}")
    
    for var in required_env:
        if not var:
            logger.error("Missing required environment variable")
            raise EnvironmentError(f"Required environment variable not set")

    # Create an observer and handler
    observer = Observer()
    handler = TokenFileHandler()
    
    # Schedule watching the directory containing the token
    token_dir = str(Path(TOKEN_PATH).parent)
    observer.schedule(handler, token_dir, recursive=True)
    
    # Start the observer
    observer.start()
    logger.info(f"Started watching {TOKEN_PATH} for changes...")
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        logger.info("Stopping token watcher...")
    
    observer.join()

if __name__ == "__main__":
    main()
