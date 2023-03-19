from concurrent.futures import wait
from prowler.lib.logger import logger
from functools import wraps
import time


def thread_per_region(function): 
    '''
    Passes the decorated function 
    Each thread has intialised the self.regional_client variable, one region per thread. Use this in the logic of the wrapped function
    '''
    def wrapper(*args,**kwargs):
        self = args[0]
        futures = [self.regional_pool.submit(function,self) for _ in self.regions]
        futures, _ = wait(futures)
        pass
    return wrapper


def thread_per_item(attribute):
    '''
    Creates a thread pool, and passes in each item from an attribute defined for self (ie "log_groups" for self.log_groups ) to the decorated function
    Will then wait for the futures to complete
    It is assumed that 
    - All changes that need to be made when invoking a function are performed on the self object (ie adding resources to self.log_groups)
    - It does not handle returned values, can be altered to do so
    '''
    def decorate(fn):
        @wraps(fn)
        def wrapper(*args,**kwargs):
            self = args[0]
            resource_iterable = getattr(self,attribute)
            futures = [self.general_pool.submit(fn,self,resource) for resource in resource_iterable]
            futures, _ = wait(futures)
            pass
        return wrapper
    return decorate


def try_catch(function): 
    '''
    Can be used to implement the try-catch strategy used throughout prowler. However, the module and filename fields in the logs then comes up as 'decorators' and 'decorators.py', instead of the actual module the error occured in.
    '''
    def wrapper(*args,**kwargs):
        self = args[0]
        try:
            return function(*args, **kwargs)
        except Exception as error:
            logger.error(
                f"{self.regional_client.region} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
    return wrapper

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


