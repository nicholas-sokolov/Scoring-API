import logging
import time

from functools import wraps

import tarantool

logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(levelname).1s %(message)s', datefmt='%Y.%m.%d %H:%M:%S')


def retry(count):
    """ Attempt of set connection with tarantool server
    :param int count: Number of attempts. Pause during 0.5 sec between attempts
    :return: Connection or None
    """
    def wrapped(func):
        @wraps(func)
        def decorated(*args):
            nonlocal count
            while count:
                try:
                    return func(*args)
                except tarantool.error.NetworkError:
                    logging.info('Try connect...')
                    time.sleep(0.5)
                count -= 1
            return None
        return decorated
    return wrapped


class TarantoolConnector:

    def __init__(self, login='test', password='test1234', space='test1', host='localhost', port=3301):
        self.connection = None
        self.login = login
        self.password = password
        self.space = space
        self.host = host
        self.port = port
        self._cache = {}
        self.set_connection()

    @retry(10)
    def connect(self):
        self.connection = tarantool.connect(self.host, self.port)

    def set_connection(self):
        self.connect()
        if self.connection is None:
            logging.error('Connection refused')
            return
        logging.info('Connection was installed')
        self.connection.authenticate(self.login, self.password)

    def get(self, key):
        """  Get value from storage
        :param str key:
        :return: String
        """
        value = self.connection.select(self.space, key)
        return value.data or None

    def cache_get(self, key):
        if self._cache.get(key):
            value, time_cache = self._cache.get(key)
            if time.time() < time_cache:
                logging.info('Value was received from cache')
                return value
        logging.info('No cache')
        return None

    def set(self, key, value):
        self.connection.replace(self.space, (key, value))

    def cache_set(self, key, value, cache_time):
        """ Set to cache storage
        :param str key:
        :param str value:
        :param int|float cache_time: minutes
        """
        self._cache[key] = (value, time.time() + cache_time * 60)
