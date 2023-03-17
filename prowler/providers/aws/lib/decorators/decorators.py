import multiprocessing
from prowler.providers.aws.lib.audit_info.audit_info import current_audit_info
from prowler.providers.aws.aws_provider import generate_regional_clients, gen_regions_for_service, AWS_Provider
from concurrent.futures import ThreadPoolExecutor, wait
from functools import wraps
import time


def threading_regional(function):
    pass
    def wrapper(*args,**kwargs):
        self = args[0]
        futures = [self.regional_pool.submit(function,self) for region in self.regions]
        futures, _ = wait(futures)
        pass
    return wrapper


def threading_global(attribute):
    def decorate(fn):
        @wraps(fn)
        def wrapper(*args,**kwargs):
            self = args[0]
            resource_iterable = getattr(self,attribute)
            futures = [self.global_pool.submit(fn,self,resource) for resource in resource_iterable]
            futures, _ = wait(futures)
            pass
        return wrapper
    return decorate


def timeit(func):
    @wraps(func)
    def timeit_wrapper(*args, **kwargs):
        start_time = time.perf_counter()
        result = func(*args, **kwargs)
        end_time = time.perf_counter()
        total_time = end_time - start_time
        print(f'Function {func.__name__}{args} {kwargs} Took {total_time:.4f} seconds')
        return result
    return timeit_wrapper

# def threading_pool(self,function):
#     def worker_intializer_function():
#         aws_provider = AWS_Provider(self.audit_info)

#     def wrapper():
#         with ThreadPoolExecutor(max_workers=len(self.regions)) as executor:
#                 futures = [executor.submit(function, self, s3_client, task) for region in self.regions]
#         pass
#     return wrapper


