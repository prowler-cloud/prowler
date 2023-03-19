
from prowler.providers.aws.aws_provider import generate_regional_clients, generate_regions_for_service
from concurrent.futures import ThreadPoolExecutor, wait
from threading import current_thread, local

def regional_worker_intializer_function(regions,regional_clients,local_context):
    # 1 thread per region. This function intializes the regional_client for each thread 
    thread = current_thread()
    thread_index = int(thread.name.split('_')[-1])
    current_region = regions[thread_index]
    # self.regional_client is mapped to self.local_context.regional_client using a getter in the Service class
    local_context.regional_client = next(regional_client for region,regional_client in regional_clients.items() if region==current_region)
    local_context.regional_client.region = current_region


class Service():
    def __init__(self, service, audit_info):
        self.service = service
        self.audit_info = audit_info
        self.session = audit_info.audit_session
        self.audited_account = audit_info.audited_account
        self.audited_partition = audit_info.audited_partition
        self.audit_resources = audit_info.audit_resources

        self.regions = generate_regions_for_service(self.service, audit_info)
        self.regional_clients = generate_regional_clients(self.service, audit_info)

        print(f"Creating regional pool with {len(self.regions)} workers")
        # Local_context is used to store per-thread information. In this case it just stores self.regional_client for each thread. The intializer function sets up each thread so that there is 1 per region
        self.local_context = local()
        self.regional_pool = ThreadPoolExecutor(
                                max_workers=len(self.regions),
                                initializer=regional_worker_intializer_function, 
                                initargs=(self.regions,self.regional_clients,self.local_context)
                                )
        self.general_pool = ThreadPoolExecutor(
                                #max_workers defaults to (# of processors)x5
                                )

    @property
    def regional_client(self):
        return self.local_context.regional_client
    