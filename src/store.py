import logging
import time

import tarantool

logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(levelname).1s %(message)s', datefmt='%Y.%m.%d %H:%M:%S')


class TarantoolConnector:

    def __init__(self, login, password, space, host='localhost', port=3301):
        self.login = login
        self.password = password
        self.space = space
        self.host = host
        self.port = port
        self._cache = {}
        self.error = ''
        self.code = None

    def get(self, key):
        value = None
        connect = self.set_connect()
        try:
            connect.authenticate(self.login, self.password)
            value = connect.select(self.space, key)
            if value:
                value = value.data
        except (tarantool.error.SchemaError, tarantool.error.DatabaseError) as err:
            self.code, self.error = err.args
            logging.error('Connection is failed ({}, {})'.format(self.code, self.error))
        connect.close()
        return value

    def set(self, key, value):
        connect = self.set_connect()
        try:
            connect.authenticate(self.login, self.password)
            connect.replace(self.space, (key, value))
        except (tarantool.error.SchemaError, tarantool.error.DatabaseError) as err:
            self.code, self.error = err.args
            logging.error('Connection is failed ({}, {})'.format(self.code, self.error))
        connect.close()

    def cache_get(self, key):
        if self._cache.get(key):
            value, time_cache = self._cache.get(key)
            if time.time >= time_cache:
                return value
        return None

    def cache_set(self, key, value, cache_time):
        self._cache[key] = (value, time.time() + cache_time)
        self.set(key, value)

    def set_connect(self, timeout=30):
        """ Setup of connection with tarantool server

        :param int timeout: Timeout for tries of connection, in seconds
        :return: None is connection is failed or Connection
        """
        start_time = time.time()
        while timeout > time.time() - start_time:
            logging.info('Try to connect... Timeout ({:.0f}s.)'.format(timeout - (time.time() - start_time)))
            try:
                connection = tarantool.connect(self.host, self.port)
                logging.info('Connection was installed')
                return connection
            except tarantool.error.NetworkError as err:
                self.code, self.error = err.errno, err.message
                continue
        logging.error('Connection is failed ({}, {})'.format(self.code, self.error))
