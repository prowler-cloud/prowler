import threading

from lib.logger import logger
from providers.aws.aws_provider import generate_regional_clients


################### CLOUDTRAIL
class Cloudtrail:
    def __init__(self, audit_info):
        self.service = "cloudtrail"
        self.session = audit_info.audit_session
        self.account = audit_info.audited_account
        self.regional_clients = generate_regional_clients(self.service, audit_info)
        self.trails = []
        self.trail_status = []
        self.__threading_call__(self.__get_trails__)
        self.__threading_call__(self.__get_trail_status__(self.trails))

        def __threading_call__(self, call):
            threads = []
            for regional_client in self.regional_clients.values():
                threads.append(threading.Thread(target=call, args=(regional_client,)))
                for t in threads:
                    t.start()
                for t in threads:
                    t.join()

        def __get_trails__(self, regional_client):
            logger.info("Cloudtrail - Getting trails...")
            try:
                describe_trails = regional_client.describe_trails()["trailList"]
                for trail in describe_trails:
                    self.trails.append(trail)

            except Exception as error:
                logger.error(
                    f"{regional_client.region} -- {error.__class__.__name__}: {error}"
                )

        def __get_trail_status__(self, trail_list, regional_client):
            logger.info("Cloudtrail - Getting trail status")
            try:
                trail_status = []
                for trail in trail_list:
                    status = regional_client.get_trail_status(Name=trail["Name"])
                    trail_status.append(status)

            except Exception as error:
                logger.error(
                    f"{regional_client.region} -- {error.__class__.__name__}: {error}"
                )
