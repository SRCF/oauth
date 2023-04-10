"""
requests Session for connecting to Hydra admin API.

This uses ansible templates to fill in the socket path
"""

import requests
import socket

from urllib.parse import urljoin
from urllib3.connection import HTTPConnection
from urllib3.connectionpool import HTTPConnectionPool
from requests.adapters import HTTPAdapter

from typing import Optional


class Connection(HTTPConnection):
    def __init__(self):
        super().__init__("localhost")

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.connect("{{ hydra_admin_api }}")


class ConnectionPool(HTTPConnectionPool):
    def __init__(self):
        super().__init__("localhost")

    def _new_conn(self):
        return Connection()


class Adapter(HTTPAdapter):
    def get_connection(self, url, proxies=None):
        return ConnectionPool()


class HydraSession(requests.Session):
    def __init__(self):
        super(HydraSession, self).__init__()
        self.mount("http://hydra/", Adapter())

    def request(self, method, url, **kwargs):
        # Strip leading '/' on provided `url` values to stop urljoin() from
        # removing the required '/admin/' subpath
        url = urljoin("http://hydra/admin/", url.lstrip('/'))
        return super().request(method, url, **kwargs)


class HydraClient:
    def __init__(self):
        self._session = HydraSession()

    def _get(self, *args, **kwargs):
        return self._session.get(*args, **kwargs)

    def _post(self, *args, **kwargs):
        return self._session.post(*args, **kwargs)

    def get_client_by_id(self, client_id: str):
        resp = self._get(f"/clients/{client_id}")
        if resp.status_code == 200:
            return resp.json(), resp
        return None, resp

    def introspect_token(self, token: str, scopes: Optional[str] = None):
        request_data = {"token": token}
        if scopes is not None:
            request_data["scopes"] = scopes
        resp = self._post("/oauth2/introspect", data=request_data)
        if resp.status_code == 200:
            return resp.json(), resp
        return None, resp


session = HydraSession()
