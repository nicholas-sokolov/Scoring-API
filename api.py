#!/usr/bin/env python
# -*- coding: utf-8 -*-

import datetime
import hashlib
import json
import logging
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer
from optparse import OptionParser

from src import scoring

logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(levelname).1s %(message)s', datefmt='%Y.%m.%d %H:%M:%S')

SALT = "Otus"
ADMIN_LOGIN = "admin"
ADMIN_SALT = "42"
OK = 200
BAD_REQUEST = 400
FORBIDDEN = 403
NOT_FOUND = 404
INVALID_REQUEST = 422
INTERNAL_ERROR = 500
ERRORS = {
    BAD_REQUEST: "Bad Request",
    FORBIDDEN: "Forbidden",
    NOT_FOUND: "Not Found",
    INVALID_REQUEST: "Invalid Request",
    INTERNAL_ERROR: "Internal Server Error",
}
UNKNOWN = 0
MALE = 1
FEMALE = 2
GENDERS = {
    UNKNOWN: "unknown",
    MALE: "male",
    FEMALE: "female",
}


class ValidationError(Exception):

    def __init__(self, *args):
        super().__init__(*args)
        if args:
            logging.error('Field {}'.format(args[0]))


class Field:
    """ Main class (descriptor) for fields

    :arg bool required: Should be set to True if field is required. By default not required.
    :arg bool nullable: Should be set to True if field can't be is empty. By default can be empty.

    """

    def __init__(self, required=False, nullable=True):
        self.required = required
        self.nullable = nullable
        self.__value = None

    def __set__(self, instance, value):
        self.validate(value)
        self.set(value)

    def __get__(self, instance, owner):
        return self.__value

    def __set_name__(self, owner, name):
        self.instance_name = name

    def set(self, value):
        self.__value = value

    def validate(self, value):
        if value is None and self.required:
            raise ValidationError("'{}' is required".format(self.instance_name))
        elif not isinstance(value, (int, bool)) and not value and not self.nullable:
            raise ValidationError("'{}' value cannot be empty".format(self.instance_name))


class CharField(Field):
    """ String """

    def set(self, value):
        if value and not isinstance(value, str):
            raise ValidationError("'{}' must be a string".format(self.instance_name))
        super().set(value)


class IntegerField(Field):
    """ Number """

    def set(self, value):
        if not value:
            return
        try:
            super().set(int(value))
        except (ValueError, TypeError):
            raise ValidationError("'{}' must be a integer".format(self.instance_name))


class ArgumentsField(Field):
    """ Dict """

    def validate(self, value):
        super().validate(value)
        try:
            dict(value)
        except ValueError:
            raise ValidationError("'{}' must be a dict".format(self.instance_name))


class EmailField(CharField):
    """ String that contains '@' """

    def validate(self, value):
        super().validate(value)
        if value and '@' not in value:
            raise ValidationError("'{}' does not contain a '@' char".format(self.instance_name))


class PhoneField(Field):
    """ String or Number that has length = 11 and starts with '7' """

    def validate(self, value):
        super().validate(value)
        if not value:
            return
        try:
            if len(str(value)) != 11 or not str(value).startswith('7'):
                raise ValidationError("'{}' length should be equal 11 and starts with '7' ".format(self.instance_name))
        except TypeError:
            raise ValidationError("'{}' value should be a string or integer type".format(self.instance_name))


class DateField(CharField):
    """ String with format DD.MM.YYYY """

    def validate(self, value):
        if not value:
            return
        try:
            datetime.datetime.strptime(value, '%d.%m.%Y')
        except (TypeError, ValueError):
            raise ValidationError("'{}' value should have DD.MM.YYYY format".format(self.instance_name))


class BirthDayField(DateField):
    """ Date from which 70 years still haven't passed """

    def validate(self, value):
        super().validate(value)
        if not value:
            return
        date = datetime.datetime.strptime(value, '%d.%m.%Y')
        if date.year < datetime.date.today().year - 70:
            raise ValidationError("'{}' must not be older than 70 ".format(self.instance_name))


class GenderField(IntegerField):
    """ Number which define gender sing (0 - UNKNOWN, 1 - MALE, 2 - FEMALE) """

    def validate(self, value):
        super().validate(value)
        if value and value not in (UNKNOWN, MALE, FEMALE):
            raise ValidationError("'{}' value must be (0 - UNKNOWN, 1 - MALE, 2 - FEMALE)".format(self.instance_name))


class ClientIDsField(Field):

    def validate(self, value):
        super().validate(value)
        if not isinstance(value, (list, tuple)):
            raise ValidationError("'{}' value must be of list or tuple type".format(self.instance_name))
        if value:
            for item in value:
                if not isinstance(item, int):
                    raise ValidationError("'{}' must be contains integer values".format(self.instance_name))


class ClientsInterestsRequest:
    client_ids = ClientIDsField(required=True, nullable=False)
    date = DateField(required=False, nullable=True)

    def __init__(self, parent):
        self.parent = parent
        self.is_valid = True
        self.__fill_data()

    def __fill_data(self):
        try:
            self.client_ids = self.parent.arguments.get('client_ids')
            self.date = self.parent.arguments.get('date')
        except ValidationError:
            self.is_valid = False

    def get_response(self):
        response = {}
        for item in self.client_ids:
            response[str(item)] = scoring.get_interests(None, None)
        return response


class OnlineScoreRequest:
    first_name = CharField(required=False, nullable=True)
    last_name = CharField(required=False, nullable=True)
    email = EmailField(required=False, nullable=True)
    phone = PhoneField(required=False, nullable=True)
    birthday = BirthDayField(required=False, nullable=True)
    gender = GenderField(required=False, nullable=True)

    def __init__(self, parent):
        self.parent = parent
        self.is_valid = True
        self.__response = {}
        self.__fill_data()
        self.__validate()

    def __fill_data(self):
        try:
            self.first_name = self.parent.arguments.get('first_name')
            self.last_name = self.parent.arguments.get('last_name')
            self.email = self.parent.arguments.get('email')
            self.phone = self.parent.arguments.get('phone')
            self.birthday = self.parent.arguments.get('birthday')
            self.gender = self.parent.arguments.get('gender')
        except ValidationError:
            self.is_valid = False

    def __validate(self):
        if None in (self.phone, self.email) \
                and None in (self.first_name, self.last_name) \
                and None in (self.gender, self.birthday):
            self.is_valid = False

    def get_response(self):
        if self.parent.is_admin:
            self.__response['score'] = 42
        else:
            score = scoring.get_score(None, self.phone, self.email, self.birthday,
                                      self.gender, self.first_name, self.last_name)
            self.__response['score'] = score
        return self.__response


class MethodRequest:
    account = CharField(required=False, nullable=True)
    login = CharField(required=True, nullable=True)
    token = CharField(required=True, nullable=True)
    arguments = ArgumentsField(required=True, nullable=True)
    method = CharField(required=True, nullable=False)

    def __init__(self, request_data):
        self.request_data = request_data
        self.response = ''
        self.code = OK
        self.__is_valid = True
        self.__fill_data()
        self.__get_response()

    @property
    def is_admin(self):
        return self.login == ADMIN_LOGIN

    @property
    def is_valid(self):
        return self.__is_valid is True

    def __fill_data(self):
        request_body = self.request_data.get('body')
        if request_body is None:
            logging.error("'body' not found.\nRequest: {}".format(self.request_data))
            self.__is_valid = False
            return
        try:
            self.login = request_body.get('login')
            self.account = request_body.get('account')
            self.token = request_body.get('token')
            self.method = request_body.get('method')
            self.arguments = request_body.get('arguments')
        except ValidationError:
            self.__is_valid = False

    def __get_response(self):
        if not self.is_valid:
            self.response = ERRORS[INVALID_REQUEST]
            self.code = INVALID_REQUEST
        elif not check_auth(self):
            self.response = ERRORS[FORBIDDEN]
            self.code = FORBIDDEN
        else:
            if self.method == 'online_score':
                method = OnlineScoreRequest(self)
            elif self.method == 'clients_interests':
                method = ClientsInterestsRequest(self)
            else:
                self.response = ERRORS[INVALID_REQUEST]
                self.code = INVALID_REQUEST
                logging.error("'{}' this method is unknown".format(self.method))
                return
            if not method.is_valid:
                self.response = ERRORS[INVALID_REQUEST]
                self.code = INVALID_REQUEST
            else:
                self.response = method.get_response()
                self.code = OK


def check_auth(request):
    if request.is_admin:
        digest = hashlib.sha512((datetime.datetime.now().strftime("%Y%m%d%H") + ADMIN_SALT).encode()).hexdigest()
    else:
        digest = hashlib.sha512((request.account + request.login + SALT).encode()).hexdigest()
    if digest == request.token:
        return True
    return False


def method_handler(request, ctx, store):
    logging.info('Request {}, context {}, settings {}'.format(request, ctx, store))
    request_instance = MethodRequest(request)
    return request_instance.response, request_instance.code


class MainHTTPHandler(BaseHTTPRequestHandler):
    router = {
        "method": method_handler
    }
    store = None

    def get_request_id(self, headers):
        return headers.get('HTTP_X_REQUEST_ID', uuid.uuid4().hex)

    def do_POST(self):
        response, code = {}, OK
        context = {"request_id": self.get_request_id(self.headers)}
        request = None
        try:
            data_string = self.rfile.read(int(self.headers['Content-Length']))
            request = json.loads(data_string)
        except:
            code = BAD_REQUEST

        if request:
            path = self.path.strip("/")
            logging.info("%s: %s %s" % (self.path, data_string, context["request_id"]))
            if path in self.router:
                try:
                    response, code = self.router[path]({"body": request, "headers": self.headers}, context, self.store)
                except Exception as e:
                    logging.exception("Unexpected error: %s" % e)
                    code = INTERNAL_ERROR
            else:
                code = NOT_FOUND

        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        if code not in ERRORS:
            r = {"response": response, "code": code}
        else:
            r = {"error": response or ERRORS.get(code, "Unknown Error"), "code": code}
        context.update(r)
        logging.info(context)
        self.wfile.write(json.dumps(r))
        return


if __name__ == "__main__":
    op = OptionParser()
    op.add_option("-p", "--port", action="store", type=int, default=8080)
    op.add_option("-l", "--log", action="store", default=None)
    (opts, _args) = op.parse_args()
    logging.basicConfig(filename=opts.log)
    server = HTTPServer(("localhost", opts.port), MainHTTPHandler)
    logging.info("Starting server at %s" % opts.port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    server.server_close()
