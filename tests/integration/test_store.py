import time
import pytest

from src.store import MemcachedConnector


@pytest.fixture(scope='module')
def store():
    store_instance = MemcachedConnector()
    return store_instance


def test_get_nonexistent_key(store):
    assert store.get('my key') is None


def test_set_key(store):
    store.set('key1', 'value1')
    assert store.get('key1')


def test_set_cached_storage(store):
    store.cache_set('key2', 'value2', 1)
    assert store.cache_get('key2')


def test_cleanup_cache(store):
    store.cache_set('key3', 'value3', 0.02)
    time.sleep(5)
    assert store.cache_get('key3') is None


def test_store_connection(store):
    assert store.client is not None


@pytest.mark.parametrize('args', [
    ("0", "data0"),
    ("1", "data1"),
    ("2", "data2"),
    ("3", "data3"),
    ("4", "data4"),
])
def test_store_data_set(args, store):
    key, value = args
    store.set(key, value)
    response = store.get(key)
    assert response == value
