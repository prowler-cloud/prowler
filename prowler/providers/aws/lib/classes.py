
from prowler.providers.aws.aws_provider import generate_regional_clients, gen_regions_for_service, AWS_Provider
import multiprocessing
from concurrent.futures import ThreadPoolExecutor
from threading import current_thread, local

def regional_worker_intializer_function(regions,regional_clients,local_context):
    # 1 thread per region. This function intializes the regional_client for each thread 
    thread = current_thread()
    thread_index = int(thread.name.split('_')[-1])
    current_region = regions[thread_index]
    local_context.regional_client = next(regional_client for region,regional_client in regional_clients.items() if region==current_region)
    local_context.regional_client.region = current_region


class Service():
    def __init__(self, service, audit_info):
        self.service = service
        self.regions = gen_regions_for_service(self.service, audit_info)
        self.audit_info = audit_info
        self.regional_clients = generate_regional_clients(self.service, audit_info)
        print(f"Creating regional pool with {len(self.regions)} workers")
        self.local_context = local()
        self.regional_pool = ThreadPoolExecutor(
                                max_workers=len(self.regions),
                                initializer=regional_worker_intializer_function, 
                                initargs=(self.regions,self.regional_clients,self.local_context)
                                )
        self.global_pool = ThreadPoolExecutor(
                                #max_workers defaults to (# of processors)x5
                                )

    @property
    def regional_client(self):
        return self.local_context.regional_client

    # @property
    # def regional_clients(self):
    #     return self.local_context.regional_clients
    
    # @regional_clients.setter
    # def regional_clients(self,x):
    #     self.__regional_clients = x