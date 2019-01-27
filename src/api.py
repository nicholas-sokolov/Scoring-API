#!/usr/bin/env python
# -*- coding: utf-8 -*-

import abc
import json
import datetime
import logging
import hashlib
import uuid
from optparse import OptionParser
from http.server import BaseHTTPRequestHandler, HTTPServer

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
    pass


class Field:

    def __init__(self, required=False, nullable=True):
        self.required = required
        self.nullable = nullable
        self.__value = None

    def __set__(self, instance, value):
        self.validate(value)
        self.set(value)

    def __get__(self, instance, owner):
        return self.__value

    def set(self, value):
        self.__value = value

    def validate(self, value):
        if value is None and self.required:
            raise ValidationError()
        elif not isinstance(value, (int, bool)) and not value and not self.nullable:
            raise ValidationError()


class CharField(Field):
    """ String """

    def set(self, value):
        if value and not isinstance(value, str):
            raise ValidationError()
        super().set(value)


class IntegerField(Field):
    """ Number """

    def set(self, value):
        if not value:
            return
        try:
            super().set(int(value))
        except (ValueError, TypeError):
            raise ValidationError()


class ArgumentsField(Field):
    """ Dict """

    def validate(self, value):
        super().validate(value)
        try:
            dict(value)
        except ValueError:
            raise ValidationError()


class EmailField(CharField):
    """ String that contains '@' """

    def validate(self, value):
        super().validate(value)
        if value and '@' not in value:
            raise ValidationError()


class PhoneField(CharField, IntegerField):
    """ String or Number that has length = 11 and starts with '7' """

    def validate(self, value):
        super().validate(value)
        try:
            if len(str(value)) != 11 or not str(value).startswith('7'):
                raise ValidationError()
        except TypeError:
            raise ValidationError()


class DateField(CharField):
    """ String with format DD.MM.YYYY """

    def set(self, value):
        try:
            super().set(datetime.datetime.strptime(value, '%d.%m.%Y'))
        except ValueError:
            raise ValidationError()


class BirthDayField(DateField):
    """ Date from which 70 years still haven't passed """

    def validate(self, value):
        super().validate(value)
        date = datetime.datetime.strptime(value, '%d.%m.%Y')
        if date.year < datetime.date.today().year - 70:
            raise ValidationError


class GenderField(IntegerField):
    """ Number which define gender sing (0 - UNKNOWN, 1 - MALE, 2 - FEMALE) """

    def validate(self, value):
        super().validate(value)
        if value and value not in (UNKNOWN, MALE, FEMALE):
            raise ValidationError


class ClientIDsField(IntegerField):
    pass


class ClientsInterestsRequest:
    client_ids = ClientIDsField(required=True)
    date = DateField(required=False, nullable=True)

    def __init__(self, request_data):
        self.request_data = request_data
        self.is_valid = False


class OnlineScoreRequest:
    first_name = CharField(required=False, nullable=True)
    last_name = CharField(required=False, nullable=True)
    email = EmailField(required=False, nullable=True)
    phone = PhoneField(required=False, nullable=True)
    birthday = BirthDayField(required=False, nullable=True)
    gender = GenderField(required=False, nullable=True)

    def __init__(self, request_data):
        self.request_data = request_data
        self.is_valid = True
        self.__fill_data()
        self.validate()

    def __fill_data(self):
        try:
            self.first_name = self.request_data.get('first_name')
            self.last_name = self.request_data.get('last_name')
            self.email = self.request_data.get('email')
            self.phone = self.request_data.get('phone')
            self.birthday = self.request_data.get('birthday')
            self.gender = self.request_data.get('gender')
        except ValidationError:
            self.is_valid = False

    def validate(self):
        if None in (self.phone, self.email) \
                and None in (self.first_name, self.last_name) \
                and None in (self.gender, self.birthday):
            self.is_valid = False


class MethodRequest:
    account = CharField(required=False, nullable=True)
    login = CharField(required=True, nullable=True)
    token = CharField(required=True, nullable=True)
    arguments = ArgumentsField(required=True, nullable=True)
    method = CharField(required=True, nullable=False)

    def __init__(self, request_data):
        self.request_data = request_data
        self.__is_valid = True
        self.__fill_data()

    @property
    def is_admin(self):
        return self.login == ADMIN_LOGIN

    @property
    def is_valid(self):
        return self.__is_valid is True

    def __fill_data(self):
        request_body = self.request_data.get('body')
        if request_body is None:
            logging.error('\'body\' not found.\nRequest: {}'.format(self.request_data))
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
    response, code = '', OK
    request_instance = MethodRequest(request)
    method = OnlineScoreRequest(request_instance) if request_instance.method == 'online_score' \
        else ClientsInterestsRequest(request_instance)
    if not method.is_valid:
        return ERRORS[INVALID_REQUEST], INVALID_REQUEST

    return response, code


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
    (opts, args) = op.parse_args()
    logging.basicConfig(filename=opts.log, level=logging.INFO,
                        format='[%(asctime)s] %(levelname).1s %(message)s', datefmt='%Y.%m.%d %H:%M:%S')
    server = HTTPServer(("localhost", opts.port), MainHTTPHandler)
    logging.info("Starting server at %s" % opts.port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    server.server_close()
