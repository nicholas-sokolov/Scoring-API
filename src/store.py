import logging
import time

import tarantool

logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(levelname).1s %(message)s', datefmt='%Y.%m.%d %H:%M:%S')


class TarantoolConnector:

    def __init__(self, login='test', password='test1234', space='test1', host='localhost', port=3301):
        self.connection = None
        self.login = login
        self.password = password
        self.space = space
        self.host = host
        self.port = port
        self._cache = {}
        self.error = ''
        self.code = None
        self.connect()

    def connect(self):
        try:
            self.connection = tarantool.connect(self.host, self.port)
        except tarantool.error.NetworkError as err:
            logging.error(f'{err}')
            self.code, self.error = err.args
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
