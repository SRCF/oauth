import ucam_webauth
import ucam_webauth.rsa
import ucam_webauth.flask_glue
from werkzeug.middleware.proxy_fix import ProxyFix

import os

class WLSRequest(ucam_webauth.Request):
    def __str__(self):
        query_string = ucam_webauth.Request.__str__(self)
        return "https://auth.srcf.net/wls/authenticate?" + query_string

class WLSResponse(ucam_webauth.Response):
    keys = dict()
    for kid in (2, 500, 501):
        with open('/etc/ucam_webauth_keys/pubkey{}'.format(kid), 'rb') as f:
            keys[str(kid)] = ucam_webauth.rsa.load_key(f.read())

class WLSAuthDecorator(ucam_webauth.flask_glue.AuthDecorator):
    request_class = WLSRequest
    response_class = WLSResponse
    logout_url = "https://auth.srcf.net/logout"

def upstream_wls(display_name: str):
    return WLSAuthDecorator(desc=display_name, require_ptags=None, iact=True)

def setup_app(app):
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_host=1)
    app.secret_key = os.environ['FLASK_SECRET_KEY']
    app.request_class.trusted_hosts = [os.environ["FLASK_HOSTNAME"]]
