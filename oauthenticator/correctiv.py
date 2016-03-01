"""
Custom Authenticator to use Correctiv OAuth with JupyterHub

Most of the code c/o Kyle Kelley (@rgbkrk)
"""


import json
import os

from tornado.auth import OAuth2Mixin
from tornado import gen, web

from tornado.httputil import url_concat
from tornado.httpclient import HTTPRequest, AsyncHTTPClient

from traitlets import Dict

from .oauth2 import OAuthLoginHandler, OAuthenticator

# Support github.com and github enterprise installations
CORRECTIV_HOST = os.environ.get('CORRECTIV_HOST') or 'correctiv.org'
CORRECTIV_API = '%s/api/user/' % CORRECTIV_HOST

CORRECITV_PROTOCOL = 'http'


class CorrectivMixin(OAuth2Mixin):
    _OAUTH_AUTHORIZE_URL = "%s://%s/account/authorize/" % (CORRECITV_PROTOCOL, CORRECTIV_HOST)
    _OAUTH_ACCESS_TOKEN_URL = "%s://%s/account/token/" % (CORRECITV_PROTOCOL, CORRECTIV_HOST)


class CorrectivLoginHandler(OAuthLoginHandler, CorrectivMixin):
    pass


class CorrectivOAuthenticator(OAuthenticator):

    login_service = "Correctiv"

    client_id_env = 'CORRECTIV_CLIENT_ID'
    client_secret_env = 'CORRECTIV_CLIENT_SECRET'
    login_handler = CorrectivLoginHandler

    username_map = Dict(config=True, default_value={},
                        help="""Optional dict to remap github usernames to nix usernames.

        User github usernames for keys and existing nix usernames as values.
        cf https://github.com/jupyter/oauthenticator/issues/28
        """)

    @gen.coroutine
    def authenticate(self, handler):
        code = handler.get_argument("code", False)
        if not code:
            raise web.HTTPError(400, "oauth callback made without a token")
        # TODO: Configure the curl_httpclient for tornado
        http_client = AsyncHTTPClient()

        # Exchange the OAuth code for a Correctiv Access Token
        #
        # See: https://developer.github.com/v3/oauth/

        # Correctiv specifies a POST request yet requires URL parameters
        params = dict(
            client_id=self.client_id,
            client_secret=self.client_secret,
            code=code,
            redirect_uri=self.authenticator.oauth_callback_url,
            grant_type='authorization_code'
        )

        url = CorrectivMixin._OAUTH_ACCESS_TOKEN_URL
        body_params = '&'.join('%s=%s' % x for x in params.items())
        req = HTTPRequest(url,
                          method="POST",
                          headers={"Accept": "application/json"},
                          body=body_params  # Body is required for a POST...
                          )

        resp = yield http_client.fetch(req)
        resp_json = json.loads(resp.body.decode('utf8', 'replace'))

        access_token = resp_json['access_token']

        # Determine who the logged in user is
        headers = {
            "Accept": "application/json",
            "User-Agent": "JupyterHub",
            "Authorization": "Bearer {}".format(access_token)
        }
        req = HTTPRequest("%s://%s" % (CORRECITV_PROTOCOL, CORRECTIV_API),
                          method="GET",
                          headers=headers
                          )
        resp = yield http_client.fetch(req)
        resp_json = json.loads(resp.body.decode('utf8', 'replace'))

        username = 'user%s' % resp_json["id"]

        return username
