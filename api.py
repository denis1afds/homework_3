#!/usr/bin/env python
# -*- coding: utf-8 -*-

from abc import abstractmethod, ABC
from weakref import WeakKeyDictionary
import json
import datetime
import logging
import hashlib
import uuid
from optparse import OptionParser
from http.server import HTTPServer, BaseHTTPRequestHandler
from scoring import get_score, get_interests

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
    OK: "Ok",
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

VALID_VALUE = 0
NOT_AVAILABLE_VALUE = 1
NULL_VALUE = 2
INVALID_VALUE = 3
CHECK_STATUS_VALUE = {
    VALID_VALUE: "Correct data",
    NOT_AVAILABLE_VALUE: "No data",
    NULL_VALUE: "Null data",
    INVALID_VALUE: "Invalid data"
}
DATE_FORMAT = "%d.%m.%Y"
READ_MODE_VALUE = 0
READ_MODE_CHECK = 1
READ_MODE_CONTENT = 2


class BaseField(ABC):
    """
    Abstract base data field class
    defines: get, set, set_name, check
    declare abstract method: get_valid_status
    """

    def __init__(self, **kwargs):
        self.required = kwargs.get('required', False)
        self.nullable = kwargs.get('nullable', False)
        self.data = WeakKeyDictionary()

    @abstractmethod
    def get_valid_status(self, value) -> bool:
        """
        :param self:
        :param value: setting value
        :return: valid status 0 - invalid value; 1 - valid value; 2 - empty value
        """
        pass

    def __get__(self, instance, owner):
        read_mode = getattr(instance, 'read_mode', READ_MODE_VALUE)
        if read_mode == READ_MODE_VALUE:
            return self.data.get(instance, {'value': None})['value']
        elif read_mode == READ_MODE_CHECK:
            setattr(instance, 'read_mode', READ_MODE_VALUE)
            return self.check(instance)

    def __set__(self, instance, value):
        valid_status = self.get_valid_status(value)
        self.data[instance] = \
            {'value': None if valid_status in (INVALID_VALUE, NULL_VALUE) else value,
             'validity': valid_status}

    def check(self, instance):
        check_status = self.data.get(instance, {'validity': NOT_AVAILABLE_VALUE})['validity']
        if check_status == NOT_AVAILABLE_VALUE and self.required:
            return NOT_AVAILABLE_VALUE
        elif check_status == NULL_VALUE and not self.nullable:
            return NULL_VALUE
        else:
            return check_status if check_status == INVALID_VALUE else VALID_VALUE

    def __set_name__(self, owner, name):
        """
        prepare data field
        :param owner:
        :param name:
        key - field name
        value - mode: value/check
        """
        if owner not in getattr(owner, 'data_fields'):
            setattr(owner, 'data_fields', {owner: set()})
        getattr(owner, 'data_fields')[owner].add(name)


class CharField(BaseField):
    def get_valid_status(self, value) -> int:
        """
        :param self:
        :param value: setting value
        :return: integer (0..2) valid status 0 - invalid value; 1 - valid value; 2 - empty value
        """
        if isinstance(value, str):
            return VALID_VALUE if len(value) > 0 else NULL_VALUE
        else:
            return INVALID_VALUE


class ArgumentsField(BaseField):
    def get_valid_status(self, value) -> int:
        """
        :param self:
        :param value: setting value
        :return: integer (0..2) valid status 0 - invalid value; 1 - valid value; 2 - empty value
        """
        if isinstance(value, dict):
            return VALID_VALUE if len(value) > 0 else NULL_VALUE
        else:
            return INVALID_VALUE


class EmailField(CharField):
    def get_valid_status(self, value) -> int:
        """
        :param self:
        :param value: setting value
        :return: integer (0..2) valid status 0 - invalid value; 1 - valid value; 2 - empty value
        """
        if isinstance(value, str):
            if len(value) == 0:
                return NULL_VALUE
            else:
                return VALID_VALUE if '@' in value else INVALID_VALUE
        else:
            return INVALID_VALUE


class PhoneField(CharField):
    def get_valid_status(self, value) -> int:
        """
        :param self:
        :param value: setting value
        :return: integer (0..2) valid status 0 - invalid value; 1 - valid value; 2 - empty value
        """
        if isinstance(value, str | int):
            value = str(value)
            data_length = len(value)
            if data_length == 0:
                return NULL_VALUE
            else:
                return VALID_VALUE if data_length == 11 and value[0] == '7' else INVALID_VALUE
        else:
            return INVALID_VALUE


class DateField(BaseField):
    def get_valid_status(self, value) -> int:
        """
        :param self:
        :param value: setting value
        :return: integer (0..2) valid status 0 - invalid value; 1 - valid value; 2 - empty value
        """
        if isinstance(value, str):
            if len(value) == 0:
                return NULL_VALUE
            else:
                try:
                    datetime.datetime.strptime(value, DATE_FORMAT)
                    return VALID_VALUE
                except ValueError:
                    return INVALID_VALUE
        else:
            return INVALID_VALUE


class BirthDayField(DateField):
    def get_valid_status(self, value) -> int:
        """
        :param self:
        :param value: setting value
        :return: integer (0..2) valid status 0 - invalid value; 1 - valid value; 2 - empty value
        """
        valid_status = super().get_valid_status(value)
        if valid_status == VALID_VALUE:
            birthday_date = datetime.datetime.strptime(value, DATE_FORMAT)
            today = datetime.datetime.today()
            if today.year - birthday_date.year - \
                    ((today.month, today.day) < (birthday_date.month, birthday_date.day)) >= 70:
                return INVALID_VALUE
        return valid_status


class GenderField(BaseField):
    def get_valid_status(self, value) -> int:
        """
        :param self:
        :param value: setting value
        :return: integer (0..2) valid status 0 - invalid value; 1 - valid value; 2 - empty value
        """
        return VALID_VALUE if value in (0, 1, 2) else INVALID_VALUE


class ClientIDsField(BaseField):
    def get_valid_status(self, value) -> int:
        """
        :param self:
        :param value: setting value
        :return: integer (0..2) valid status 0 - invalid value; 1 - valid value; 2 - empty value
        """
        if isinstance(value, list) and all(isinstance(item, int) for item in value):
            return VALID_VALUE if len(value) > 0 else NULL_VALUE
        else:
            return INVALID_VALUE

    def __len__(self):
        return len(self.data)


class BaseRequest(ABC):
    """
    Base methods for request class
    """
    data_fields = dict()

    def __init__(self, arguments_dict):
        if arguments_dict is not None:
            for field_name in (self.content & set(arguments_dict)):
                setattr(self, field_name, arguments_dict[field_name])
        self.is_valid = len(self.errors_check) == 0
        self.read_mode = READ_MODE_VALUE

    def check_data(self, data_field: str) -> int:
        """
        return error state data_field variable
        :param data_field:
        :return: int constant one of (VALID_VALUE, NULL_VALUE, INVALID_VALUE)
        """
        self.read_mode = READ_MODE_CHECK
        return getattr(self, data_field)

    @property
    def errors_check(self) -> dict:
        """
        :return: dict fields -> error_name
        there are no errors if length of returned value (dict) is null
        """
        all_fields_check_status = dict((field, self.check_data(field)) for field in self.content)
        return (
            dict((field, CHECK_STATUS_VALUE[check_status])
                 for field, check_status
                 in all_fields_check_status.items() if check_status != VALID_VALUE))

    @property
    def content(self) -> set:
        return self.data_fields.get(self.__class__, set())

    def __str__(self):
        result_state = ""
        for field in self.content:
            result_state += "\n" if len(result_state) != 0 else ""
            result_state += ("{}:\t{} \t ({})".
                             format(field, getattr(self, field),
                                    CHECK_STATUS_VALUE[self.check_data(field)]))
        return result_state


class MethodRequest(BaseRequest):
    """
    Root class for processing the request
    """
    account = CharField(required=False, nullable=True)
    login = CharField(required=True, nullable=True)
    token = CharField(required=True, nullable=True)
    arguments = ArgumentsField(required=True, nullable=True)
    method = CharField(required=True, nullable=False)

    @property
    def is_admin(self):
        return self.login == ADMIN_LOGIN


class OnlineScoreRequest(BaseRequest):
    first_name = CharField(required=False, nullable=True)
    last_name = CharField(required=False, nullable=True)
    email = EmailField(required=False, nullable=True)
    phone = PhoneField(required=False, nullable=True)
    birthday = BirthDayField(required=False, nullable=True)
    gender = GenderField(required=False, nullable=True)

    def __init__(self, method_request: MethodRequest):
        super().__init__(method_request.arguments)
        self.result_function = (lambda *arguments: 42) if method_request.is_admin else get_score
        if self.is_valid:
            self.result = {'score': self.result_function(
                None, self.phone, self.email, self.birthday,
                self.gender, self.first_name, self.last_name)}
        else:
            self.result = {}

    @property
    def errors_check(self) -> dict:
        errors_dict = super().errors_check
        if len(errors_dict) > 0:
            return errors_dict

        check_fields = (('first_name', 'last_name'), ('email', 'phone'), ('birthday', 'gender'))
        check_list = map(lambda check_pair:
                         getattr(self, check_pair[0]) is not None and
                         getattr(self, check_pair[1]) is not None, check_fields)
        if not any(check_list):
            errors_dict = {
                'empty pair': list(
                    (fields_pair for fields_pair, filled_flag in zip(check_fields, check_list)
                     if not filled_flag))}
        return errors_dict

    @property
    def context(self):
        return {'has': list((field for field in self.content if getattr(self, field) is not None))}


class ClientsInterestsRequest(BaseRequest):
    client_ids = ClientIDsField(required=True)
    date = DateField(required=False, nullable=True)

    def __init__(self, method_request: MethodRequest):
        super().__init__(method_request.arguments)
        self.result_function = lambda clients_list: \
            {str(cid): get_interests(None, cid) for cid in clients_list}
        if self.is_valid:
            self.result = self.result_function(self.client_ids)

    @property
    def context(self) -> dict:
        lst = [] if self.client_ids is None else self.client_ids
        return {'nclients': 0 if lst is None else len(lst)}


def check_auth(request):
    if request.is_admin:
        digest = hashlib.sha512(
            (datetime.datetime.now().strftime("%Y%m%d%H") + ADMIN_SALT).encode(encoding='utf-8'))\
            .hexdigest()
    else:
        digest = hashlib.sha512((request.account + request.login + SALT).encode(encoding='utf-8'))\
            .hexdigest()
    if digest == request.token:
        return True
    return False


def method_handler(request: dict, ctx, store):
    method_routes = {'online_score': OnlineScoreRequest,
                     'clients_interests': ClientsInterestsRequest}
    method_request = MethodRequest(request.get('body', {}))
    if method_request.is_valid and method_request.method in method_routes:
        if not check_auth(method_request):
            logging.error("Unauthorized (access denied) login:{} token:{}".
                          format(method_request.login, method_request.token))
            return ERRORS[FORBIDDEN], FORBIDDEN
        process_request = method_routes[method_request.method](method_request)
        if process_request.is_valid:
            ctx.update(process_request.context)
            return process_request.result, OK
        else:
            return process_request.errors_check, INVALID_REQUEST
    else:
        return ERRORS[INVALID_REQUEST], INVALID_REQUEST


class MainHTTPHandler(BaseHTTPRequestHandler):
    router = {
        "method": method_handler
    }
    store = None

    @staticmethod
    def get_request_id(headers):
        return headers.get('HTTP_X_REQUEST_ID', uuid.uuid4().hex)

    def do_POST(self):
        response, code = {}, OK
        context = {"request_id": self.get_request_id(self.headers)}
        request = None
        data_string = None
        try:
            data_string = self.rfile.read(int(self.headers['Content-Length']))
            request = json.loads(data_string)
        except json.decoder.JSONDecodeError:
            code = BAD_REQUEST

        if request:
            path = self.path.strip("/")
            logging.info("%s: %s %s" % (self.path, data_string, context["request_id"]))
            if path in self.router:
                try:
                    response, code = (self.router[path]
                                      ({"body": request, "headers": self.headers},
                                       context, self.store))
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
        self.wfile.write(json.dumps(r).encode(encoding='utf-8'))
        return


if __name__ == "__main__":
    op = OptionParser()
    op.add_option("-p", "--port", action="store", type=int, default=8080)
    op.add_option("-l", "--log", action="store", default=None)
    (opts, args) = op.parse_args()
    logging.basicConfig(filename=opts.log, level=logging.INFO,
                        format='[%(asctime)s] %(levelname).1s %(message)s',
                        datefmt='%Y.%m.%d %H:%M:%S')
    server = HTTPServer(("localhost", opts.port), MainHTTPHandler)
    logging.info("Starting server at %s" % opts.port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    server.server_close()
