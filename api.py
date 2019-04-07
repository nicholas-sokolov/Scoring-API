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


class Declaration(type):

    def __new__(mcs, name, bases, attrs):
        current_fields = []
        for key, value in list(attrs.items()):
            if isinstance(value, Field):
                current_fields.append(key)
        attrs['declared_fields'] = current_fields
        return super().__new__(mcs, name, bases, attrs)


class Field:
    """ Main class (descriptor) for fields

    :arg bool required: Should be set to True if field is required. By default not required.
    :arg bool nullable: Should be set to True if field can't be is empty. By default can be empty.

    """

    def __init__(self, required=False, nullable=True):
        self.required = required
        self.nullable = nullable

    def __set__(self, instance, value):
        self.validate(value)
        if value is not None:
            instance.__dict__[self.instance_name] = self.get_convert(value)

    def __get__(self, instance, owner):
        return instance.__dict__.get(self.instance_name)

    def __set_name__(self, owner, name):
        self.instance_name = name

    def get_convert(self, value):
        return value

    def validate(self, value):
        if value is None and self.required:
            raise ValidationError("'{}' is required".format(self.instance_name))
        elif not isinstance(value, (int, bool)) and not value and not self.nullable:
            raise ValidationError("'{}' value cannot be empty".format(self.instance_name))


class CharField(Field):
    """ String """

    def validate(self, value):
        super().validate(value)
        if value is not None and not isinstance(value, str):
            raise ValidationError("'{}' must be a string".format(self.instance_name))


class IntegerField(Field):
    """ Number """

    def validate(self, value):
        super().validate(value)
        if not isinstance(value, int) and not value:
            return
        try:
            int(value)
        except (ValueError, TypeError):
            raise ValidationError("'{}' must be a integer".format(self.instance_name))

    def get_convert(self, value):
        if not isinstance(value, int) and not value:
            return None
        return int(value)


class ArgumentsField(Field):
    """ Dict """

    def validate(self, value):
        super().validate(value)
        try:
            dict(value)
        except (ValueError, TypeError):
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
        if value is None:
            return
        try:
            int(value)
            if len(str(value)) != 11 or not str(value).startswith('7'):
                raise ValidationError("'{}' length should be equal 11 and starts with '7' ".format(self.instance_name))
        except (TypeError, ValueError):
            raise ValidationError("'{}' value should be a string or integer type".format(self.instance_name))


class DateField(CharField):
    """ String with format DD.MM.YYYY """

    def validate(self, value):
        if value is None:
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


class Request(metaclass=Declaration):

    def __init__(self, request):
        self.request = request
        self.error = {}
        self.code = OK
        self.fill_data(request)

    def fill_data(self, request):
        if request is None:
            logging.error("Wrong request.\nRequest: {}".format(request))
            self.code = INVALID_REQUEST
            self.error = "Wrong request"
            return
        for field in self.declared_fields:
            try:
                setattr(self, field, request.get(field))
            except ValidationError as err:
                self.error[field] = str(err)
        if self.error:
            self.code = INVALID_REQUEST


class ClientsInterestsRequest(Request):
    client_ids = ClientIDsField(required=True, nullable=False)
    date = DateField(required=False, nullable=True)


class OnlineScoreRequest(Request):
    first_name = CharField(required=False, nullable=True)
    last_name = CharField(required=False, nullable=True)
    email = EmailField(required=False, nullable=True)
    phone = PhoneField(required=False, nullable=True)
    birthday = BirthDayField(required=False, nullable=True)
    gender = GenderField(required=False, nullable=True)

    def __init__(self, arguments):
        super().__init__(arguments)
        self.__validate()

    def __validate(self):
        """ There must be at least one value pair """
        if not any([
            (self.phone and self.email),
            (self.first_name and self.last_name),
            (isinstance(self.gender, int) and self.birthday)
        ]):
            self.code = INVALID_REQUEST
            self.error = "There must be at least one value pair (phone, email), (first_name, last_name), " \
                         "(gender, birthday)"


class MethodRequest(Request):
    account = CharField(required=False, nullable=True)
    login = CharField(required=True, nullable=True)
    token = CharField(required=True, nullable=True)
    arguments = ArgumentsField(required=True, nullable=True)
    method = CharField(required=True, nullable=False)

    def __init__(self, request_data):
        super().__init__(request_data.get('body'))
        if self.code == OK:
            self.__authenticate()

    @property
    def is_admin(self):
        return self.login == ADMIN_LOGIN

    def __authenticate(self):
        if not check_auth(self):
            self.code = FORBIDDEN
            self.error = 'Authentication failed'


def check_auth(request):
    if request.is_admin:
        digest = hashlib.sha512((datetime.datetime.now().strftime("%Y%m%d%H") + ADMIN_SALT).encode()).hexdigest()
    else:
        try:
            digest = hashlib.sha512((request.account + request.login + SALT).encode()).hexdigest()
        except TypeError:
            return False
    if digest == request.token:
        return True
    return False


def get_clients_interests(method):
    """ About get clients interests

    :param ClientsInterestsRequest method:
    :return: tuple
    """
    if method.code != OK:
        return method.error, method.code
    response = {}
    for item in method.client_ids:
        response[str(item)] = scoring.get_interests(None, None)
    return response, method.code


def get_online_score(request, method):
    """ About get online score

    :param MethodRequest request:
    :param OnlineScoreRequest method:
    :return: tuple
    """
    if method.code != OK:
        return method.error, method.code
    response = {}
    if request.is_admin:
        score = 42
    else:
        score = scoring.get_score(None, method.phone, method.email, method.birthday,
                                  method.gender, method.first_name, method.last_name)
    response['score'] = score
    return response, method.code


def method_handler(request, ctx, store):
    logging.info('Request {}, context {}, settings {}'.format(request, ctx, store))

    request_instance = MethodRequest(request)
    # check request
    if request_instance.code != OK:
        return request_instance.error, request_instance.code

    if request_instance.method == 'online_score':
        method = OnlineScoreRequest(request_instance.arguments)
        response, code = get_online_score(request_instance, method)
    elif request_instance.method == 'clients_interests':
        method = ClientsInterestsRequest(request_instance.arguments)
        response, code = get_clients_interests(method)
    else:
        return {'method error': 'Unknown method'}, INVALID_REQUEST

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
    (opts, _args) = op.parse_args()
    logging.basicConfig(filename=opts.log)
    server = HTTPServer(("localhost", opts.port), MainHTTPHandler)
    logging.info("Starting server at %s" % opts.port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    server.server_close()
