
from prowler.providers.aws.aws_provider import generate_regional_clients, gen_regions_for_service, AWS_Provider
import multiprocessing
from concurrent.futures import ThreadPoolExecutor
from threading import current_thread, local

def regional_worker_intializer_function(audit_info,regions,service,local_context):
    aws_provider = AWS_Provider(audit_info,thread_provider=True)
    session = aws_provider.aws_session

    thread = current_thread()
    thread_index = int(thread.name.split('_')[-1])
    region = regions[thread_index]
    local_context.regional_client = session.client(service_name=service,region_name=region)
    local_context.regional_client.region = region

def global_worker_intializer_function(audit_info,regions,service,local_context):
    aws_provider = AWS_Provider(audit_info,thread_provider=True)
    session = aws_provider.aws_session
    regional_clients = {}
    for region in regions:
        regional_client = session.client(
            service, region_name=region, config=audit_info.session_config
        )
        regional_client.region = region
        regional_clients[region] = regional_client
    local_context.regional_clients = regional_clients

class Service():
    def __init__(self, service, audit_info):
        self.service = service
        self.regions = gen_regions_for_service(self.service, audit_info)
        self.audit_info = audit_info
        print(f"Creating regional pool with {len(self.regions)} workers")
        self.local_context = local()
        self.regional_pool = ThreadPoolExecutor(
                                max_workers=len(self.regions),
                                initializer=regional_worker_intializer_function, 
                                initargs=(audit_info,self.regions,self.service,self.local_context)
                                )
        self.global_pool = ThreadPoolExecutor(
                                #max_workers defaults to (# of processors)x5
                                initializer=global_worker_intializer_function, 
                                initargs=(audit_info,self.regions,self.service,self.local_context)
                                )

    @property
    def regional_client(self):
        return self.local_context.regional_client

    @property
    def regional_clients(self):
        return self.local_context.regional_clients
    
    # @regional_clients.setter
    # def regional_clients(self,x):
    #     self.__regional_clients = x