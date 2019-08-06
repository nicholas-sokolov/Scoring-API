import logging
import time

from functools import wraps

from pymemcache import exceptions
from pymemcache.client import base

logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(levelname).1s %(message)s', datefmt='%Y.%m.%d %H:%M:%S')


def retryer(try_attempt):

    def wrapper(func):

        @wraps(func)
        def decorated(*args, **kwargs):
            try_counter = 0
            while try_counter <= try_attempt:
                try_counter += 1
                try:
                    return func(*args, **kwargs)
                except ConnectionRefusedError as err:
                    logging.error(f'Attempt {try_counter}. {err}')

            return func(*args, **kwargs)

        return decorated

    return wrapper


class MemcachedConnector:

    def __init__(self, host='localhost', port=11211, auto_connect=True):
        self.client = None
        self.host = host
        self.port = port
        self.__local_cache = {}
        self.error_messages = []
        if auto_connect:
            self.set_connection()

    @retryer(5)
    def set_connection(self):
        self.client = base.Client((self.host, self.port))

    def get(self, key: str):
        """  Get value from storage """
        try:
            value = self.client.get(key)
        except (exceptions.MemcacheIllegalInputError, ConnectionRefusedError) as err:
            self.error_messages = err
            value = None
        if isinstance(value, bytes):
            value = value.decode()
        return value

    def cache_get(self, key: str):
        """  Get value from storage """
        value, time_cache = self.__local_cache.get(key, (None, None))
        if time_cache and time.time() < time_cache:
            logging.info('Value was received from cache')
            return value
        logging.info('No such key')
        return self.get(key)

    def set(self, key: str, value: str) -> None:
        """  Set cache to the storage """
        self.client.set(key, value)

    def cache_set(self, key: str, value: str, cache_time: int) -> None:
        """  Set cache to the local storage """
        until_time = time.time() + cache_time * 60
        self.__local_cache[key] = (value, until_time)
