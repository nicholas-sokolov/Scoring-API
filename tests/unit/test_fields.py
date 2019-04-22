import pytest
import datetime

from src.api import CharField
from src.api import IntegerField
from src.api import ArgumentsField
from src.api import EmailField
from src.api import PhoneField
from src.api import DateField
from src.api import BirthDayField
from src.api import GenderField
from src.api import ClientIDsField
from src.api import ValidationError


class RequestExample:
    char_field = CharField()
    integer_field = IntegerField()
    arguments_field = ArgumentsField()
    email_field = EmailField()
    phone_field = PhoneField()
    date_field = DateField()
    birthday_field = BirthDayField()
    gender_field = GenderField()
    client_id_field = ClientIDsField()


@pytest.fixture()
def my_request():
    return RequestExample()


@pytest.mark.parametrize('value', [
    0, 1,
    0.01, 1.0,
    True, False,
    {'key': 1}
])
def test_exception_char_field(my_request, value):
    error = ''
    try:
        my_request.char_field = value
    except ValidationError as err:
        error = str(err)
    assert error


@pytest.mark.parametrize('value', [
    '',
    'text',
])
def test_valid_char_field(my_request, value):
    error = ''
    try:
        my_request.char_field = value
    except ValidationError as err:
        error = str(err)
    assert not error
    assert isinstance(my_request.char_field, str)


@pytest.mark.parametrize('value', [
    'text',
    {'key': 1}
])
def test_exception_integer_field(my_request, value):
    error = ''
    try:
        my_request.integer_field = value
    except ValidationError as err:
        error = str(err)
    assert error


@pytest.mark.parametrize('value', [
    1,
    999,
    0
])
def test_valid_integer_field(my_request, value):
    error = ''
    try:
        my_request.integer_field = value
    except ValidationError as err:
        error = str(err)
    assert not error
    assert isinstance(my_request.integer_field, int)


@pytest.mark.parametrize('value', [
    0, 1,
    '0', '1',
    'text',
    0.01, 1.0,
    True, False,
])
def test_exception_arguments_field(my_request, value):
    error = ''
    try:
        my_request.arguments_field = value
    except ValidationError as err:
        error = str(err)
    assert error


@pytest.mark.parametrize('value', [
    {},
    {1: 1}
])
def test_valid_arguments_field(my_request, value):
    error = ''
    try:
        my_request.arguments_field = value
    except ValidationError as err:
        error = str(err)
    assert not error
    assert isinstance(my_request.arguments_field, dict)


@pytest.mark.parametrize('value', [
    'text',
    'email.com'
])
def test_exception_email_field(my_request, value):
    error = ''
    try:
        my_request.email_field = value
    except ValidationError as err:
        error = str(err)
    assert error


@pytest.mark.parametrize('value', [
    'email@email.com'
])
def test_valid_email_field(my_request, value):
    error = ''
    try:
        my_request.email_field = value
    except ValidationError as err:
        error = str(err)
    assert not error


@pytest.mark.parametrize('value', [
    0, 1,
    '0', '1',
    'text',
    0.01, 1.0,
    True, False,
    {'key': 1},
    '89998885544', 75555555, '+79998885544'
])
def test_exception_phone_field(my_request, value):
    error = ''
    try:
        my_request.phone_field = value
    except ValidationError as err:
        error = str(err)
    assert error


@pytest.mark.parametrize('value', [
    '79998885544',
    79998885544,
])
def test_valid_phone_field(my_request, value):
    error = ''
    try:
        my_request.phone_field = value
    except ValidationError as err:
        error = str(err)
    assert not error


@pytest.mark.parametrize('value', [
    'text',
    '01.01.50', '1.01.50', '01.1.50'
])
def test_exception_date_field(my_request, value):
    error = ''
    try:
        my_request.date_field = value
    except ValidationError as err:
        error = str(err)
    assert error


@pytest.mark.parametrize('value', [
    '01.01.1950',
    '1.01.1950',
    '01.1.1950'
])
def test_valid_date_field(my_request, value):
    error = ''
    try:
        my_request.date_field = value
    except ValidationError as err:
        error = str(err)
    assert not error


@pytest.mark.parametrize('value', [
    '01.01.1948'
])
def test_exception_birthday_field(my_request, value):
    error = ''
    try:
        my_request.birthday_field = value
    except ValidationError as err:
        error = str(err)
    assert error


@pytest.mark.parametrize('value', [
    datetime.datetime.today().strftime("%d.%m.%Y"),
    f'01.01.{(datetime.datetime.today().year - 70)}',
])
def test_valid_birthday_field(my_request, value):
    error = ''
    try:
        my_request.birthday_field = value
    except ValidationError as err:
        error = str(err)
    assert not error


@pytest.mark.parametrize('value', [
    3
])
def test_exception_gender_field(my_request, value):
    error = ''
    try:
        my_request.gender_field = value
    except ValidationError as err:
        error = str(err)
    assert error


@pytest.mark.parametrize('value', [
    0,
    1,
    2,
])
def test_valid_gender_field(my_request, value):
    error = ''
    try:
        my_request.gender_field = value
    except ValidationError as err:
        error = str(err)
    assert not error


@pytest.mark.parametrize('value', [
    {1: 1},
    ('1', '1'),
    ['1', 1]
])
def test_exception_client_id_field(my_request, value):
    error = ''
    try:
        my_request.client_id_field = value
    except ValidationError as err:
        error = str(err)
    assert error


@pytest.mark.parametrize('value', [
    [],
    (),
    (1, 1),
])
def test_valid_client_id_field(my_request, value):
    error = ''
    try:
        my_request.client_id_field = value
    except ValidationError as err:
        error = str(err)
    assert not error
