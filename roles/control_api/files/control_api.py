from hydra_session import session
from flask import Flask, request, abort
import os

secret = os.environ["CONTROL_API_SECRET"]
app = Flask(__name__)

@app.before_request
def authorize():
    try:
        token = request.headers["Authorization"]
    except KeyError:
        abort(401)

    if token != secret:
        abort(401)

@app.route('/control_api/<owner>')
def endpoint(owner: str):
    return {
        "clients": [x for x in session.get('/clients').json() if x["owner"] == owner],
        "consents": session.get('/oauth2/auth/sessions/consent?subject=' + owner).json()
    }
