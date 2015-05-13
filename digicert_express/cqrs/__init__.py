import json
import getpass

from express_utils import LOGGER
from express_utils import HOST
from digicert_client.api.commands import Command
from digicert_client import Request

class LoginCommand(Command):
    def __init__(self, username, password):
        super(LoginCommand, self).__init__(customer_api_key=None,
                                           customer_name=None,
                                           **{'username': username, 'current_password': password})
        # self._headers['Content-Type'] = 'application/json'
        self.set_header('Content-Type', 'application/json')


    def get_path(self):
        return '/services/v2/user/tempkey'

    def get_params(self):
        return json.dumps(self.__dict__)

    def __str__(self):
        return json.dumps(self.__dict__, indent=2, separators=(',', ': '))

    def _subprocess_response(self, status, reason, response):
        return self._make_response(status, reason, response)


def get_temp_api_key():
    # prompt for username and password,
    LOGGER.info("You will need your Digicert account credentials to continue: ")

    username = raw_input("DigiCert Username: ")
    password = getpass.getpass("DigiCert Password: ")

    result = Request(action=LoginCommand(username, password), host=HOST).send()
    if result['http_status'] >= 300:
        raise Exception('Login failed:  %d - %s' % (result['http_status'], result['http_reason']))

    try:
        api_key = result['api_key']
        return api_key
    except KeyError:
        api_key = None
    return
