import pytest

import api

headers = {}
context = {}
store = {}


def get_response(request):
    return api.method_handler({"body": request, "headers": headers}, context, store)


def test_empty_request():
    _, code = get_response({})
    assert api.INVALID_REQUEST == code


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
