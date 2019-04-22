import time

import src.store as store

connection = store.TarantoolConnector()


def test_get_nonexistent_key():
    assert connection.get('my key') is None


def test_set_key():
    connection.set('key1', 'value1')
    assert connection.get('key1')


def test_set_cached_stoge():
    connection.cache_set('key2', 'value2', 1)
    assert connection.cache_get('key2')


def test_cleanup_cache():
    connection.cache_set('key3', 'value3', 0.02)
    time.sleep(5)
    assert connection.cache_get('key3') is None
