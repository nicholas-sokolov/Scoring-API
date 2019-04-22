import datetime
import hashlib

import pytest

import api

from src.store import TarantoolConnector

headers = {}
context = {}
store = {}


def get_response(request):
    return api.method_handler({"body": request, "headers": headers}, context, store)


def set_auth(request):
    if request.get('login') == api.ADMIN_LOGIN:
        token = hashlib.sha512((datetime.datetime.now().strftime("%Y%m%d%H") + api.ADMIN_SALT).encode()).hexdigest()
    else:
        msg = request.get("account", "") + request.get("login", "") + api.SALT
        token = hashlib.sha512(msg.encode()).hexdigest()
    request['token'] = token


def test_empty_request():
    _, code = get_response({})
    assert api.INVALID_REQUEST == code


@pytest.fixture(scope='module')
def store():
    store_instance = TarantoolConnector('test', 'test1234', 'test1')
    return store_instance


@pytest.mark.parametrize('request', [
    {'login': "m&m's", 'token': 'qwerty', 'method': "", 'arguments': {}},
    {'token': 'qwerty', 'method': "online_score", 'arguments': {}},
    {'login': "m&m's", 'method': "online_score", 'arguments': {}},
    {'login': "m&m's", 'token': 'qwerty', 'method': "online_score"},
    {'login': "m&m's", 'token': 'qwerty', 'arguments': {}},
    {'login': "m&m's", 'token': 'qwerty', 'method': "online_score", 'arguments': "123"},
    {'login': "m&m's", 'token': 'qwerty', 'method': "online_score", 'arguments': 123},
    {'login': 123, 'token': 'qwerty', 'method': "online_score", 'arguments': {}},
    {'login': "m&m's", 'token': 123, 'method': "online_score", 'arguments': {}},
    {'login': "m&m's", 'token': 'qwerty', 'method': 123, 'arguments': {}},
])
def test_invalid_request(request):
    response, code = get_response(request)
    assert api.INVALID_REQUEST == code


@pytest.mark.parametrize('request', [
    {'login': "m&m's", 'token': 'qwerty'},
    {'login': "m&m's", 'token': ''},
    {'login': "admin", 'token': 'qwerty'},
    {'login': "admin", 'token': ''},
])
def test_failed_authentication(request):
    request.update({
        'account': "m_account",
        'method': "online_score",
        'arguments': {}}
    )
    response, code = get_response(request)
    assert api.FORBIDDEN == code


@pytest.mark.parametrize('arguments', [
    {},
    {"phone": "79175002040"},
    {"phone": "89175002040", "email": "stupnikov@otus.ru"},
    {"phone": "79175002040", "email": "stupnikovotus.ru"},
    {"phone": "79175002040", "email": "stupnikov@otus.ru", "gender": -1},
    {"phone": "79175002040", "email": "stupnikov@otus.ru", "gender": "1"},
    {"phone": "79175002040", "email": "stupnikov@otus.ru", "gender": 1, "birthday": "01.01.1890"},
    {"phone": "79175002040", "email": "stupnikov@otus.ru", "gender": 1, "birthday": "XXX"},
    {"phone": "79175002040", "email": "stupnikov@otus.ru", "gender": 1, "birthday": "01.01.2000", "first_name": 1},
    {"phone": "79175002040", "email": "stupnikov@otus.ru", "gender": 1, "birthday": "01.01.2000",
     "first_name": "s", "last_name": 2},
    {"phone": "79175002040", "birthday": "01.01.2000", "first_name": "s"},
    {"email": "stupnikov@otus.ru", "gender": 1, "last_name": 2},
])
def test_invalid_score_request(arguments):
    request = {"account": "m_account", "login": "m&m", "method": "online_score", "arguments": arguments}
    set_auth(request)
    response, code = get_response(request)
    assert api.INVALID_REQUEST == code
    assert len(response) != 0


def test_store_connection(store):
    connect = store.set_connect()
    assert connect is not None


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
    assert response[0][1] == value
