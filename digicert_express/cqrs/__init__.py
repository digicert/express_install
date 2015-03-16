import json

from digicert_client.api.commands import Command


class LoginCommand(Command):
    def __init__(self, username, password):
        super(LoginCommand, self).__init__(customer_api_key=None,
                                           customer_name=None,
                                           **{'username': username, 'password': password})
        self._headers['Content-Type'] = 'application/x-www-form-urlencoded'

    def get_path(self):
        return '/services/v2/authentication/login'

    def __str__(self):
        return json.dumps(self.__dict__, indent=2, separators=(',', ': '))

    def _subprocess_response(self, status, reason, response):
        return self._make_response(status, reason, response)