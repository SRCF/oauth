# requests session for connecting to Hydra admin API

import requests
import socket
import pprint
import os

from urllib3.connection import HTTPConnection
from urllib3.connectionpool import HTTPConnectionPool
from requests.adapters import HTTPAdapter

SOCKET_LOCATION = os.environ["HYDRA_ADMIN_API"]

class Connection(HTTPConnection):
    def __init__(self):
        super().__init__("localhost")

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.connect(SOCKET_LOCATION)


class ConnectionPool(HTTPConnectionPool):
    def __init__(self):
        super().__init__("localhost")

    def _new_conn(self):
        return Connection()


class Adapter(HTTPAdapter):
    def get_connection(self, url, proxies=None):
        return ConnectionPool()

session = requests.Session()
session.mount("http://hydra/", Adapter())
