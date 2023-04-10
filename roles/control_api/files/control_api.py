import logging
import os
import time

from functools import lru_cache
from typing import Any, Dict

from flask import Flask, g, request, abort
from hydra_session import HydraClient


secret = os.environ["CONTROL_API_SECRET"]
app = Flask(__name__)
hydra_client = HydraClient()


app.logger.setLevel(logging.INFO)


@lru_cache(maxsize=256)
def _ensure_access_token_and_client(token: str) -> (bool, Dict[str, Any], Dict[str, Any]):
    """Validate that `token` is an active access token (not refresh token).

    Returns: a tuple (valid, client_info, token_info).
        valid: whether the token is an active access token.
        token_info: if `valid`, information on the access token from the Hydra API.
        client_info: if `valid`, information on the client from the Hydra API.
    """
    token_info, _ = hydra_client.introspect_token(token)
    if (
        token_info is not None and
        token_info.get("active", False) is True and
        token_info.get("token_type") == "Bearer" and
        token_info.get("token_use") == "access_token"
    ):
        client_id = token_info["client_id"]
        client_info, _ = hydra_client.get_client_by_id(client_id)
        if client_info is not None:
            return True, token_info, client_info
    return False, None, None


def _authorise_oauth2_client(auth_header: str) -> bool:
    """Try to authorise a client using an OAuth2 bearer token.

    Args:
        auth_header: the value of the Authorization header (not including the
            header name)
    """
    parts = auth_header.split(' ', maxsplit=1)
    if len(parts) != 2:
        app.logger.debug("Auth header not in 'Bearer <token>' format, OAuth2 check failed")
        return False

    scheme, token = parts
    if scheme.lower() != 'bearer':
        app.logger.debug("Auth scheme not Bearer, OAuth2 check failed")
        return False

    valid, token_info, client_info = _ensure_access_token_and_client(token)
    if (
        # Token is valid
        valid and
        # Token hasn't expired
        (token_info["exp"] > time.time()) and
        # This is a client_credentials grant (i.e. the client itself is calling us)
        ((client_id := token_info["client_id"]) == token_info["sub"]) and
        # The client is internal (i.e. allowed to call this API)
        (client_info["metadata"].get("internal", False) is True)
    ):
        g.auth = {
            "method": "oauth2",
            "client_id": client_id,
            "sub": client_id,
        }
        return True

    app.logger.debug("OAuth2 bearer token not valid or not internal client, OAuth2 check failed")
    return False


def _authorise_global_secret(auth_header: str) -> bool:
    """Try to authorise a client using the single shared API secret.

    Args:
        auth_header: the value of the Authorization header (not including the
            header name)
    """
    if auth_header == secret:
        g.auth = {
            "method": "global_secret",
        }
        return True
    return False


@app.before_request
def authorize():
    g.auth = {}

    try:
        auth_header = request.headers["Authorization"]
    except KeyError:
        abort(401)

    if not (
        _authorise_global_secret(auth_header) or
        _authorise_oauth2_client(auth_header)
    ):
        abort(401)


@app.route("/control_api/<owner>")
def owner_related(owner: str):
    """Gather OAuth2 information relating to ``owner`` for the Control Panel.

    ``owner`` should be a CRSid or group username: other values will probably
    return no results.

    Returns:
        a dict with keys "clients" and "consents".  Values for each key are
        arrays of owned clients and active consents for ``owner``, as
        returned by the Hydra API.
    """
    return {
        "clients": [x for x in hydra_client._get('/clients').json() if x["owner"] == owner],
        "consents": hydra_client._get(
            "/oauth2/auth/sessions/consent", params={"subject": owner}
        ).json()
    }


@app.route("/oauth2/introspect", methods=['POST'])
def introspect_token():
    """Introspect the OAuth2 token provided in form data under key ``token``.

    This endpoint exists to provide authenticated/authorised access to the
    corresponding Hydra admin API endpoint for trusted internal clients.

    Callers using an OAuth2 access token to authenticate themselves to this
    endpoint will only be shown introspection results for OAuth2 tokens
    originally issued under their client_id or with their client_id in the
    token's "aud" claim.
    """
    token = request.form.get("token")
    if not token:
        return ({"error": "token_missing"}, 400)

    token_info, _ = hydra_client.introspect_token(token)

    # An {"active": false} introspection result is safe to pass back to any
    # caller, which we may do here.  For any other result, the subsequent code
    # may make the result visible depending on the caller's identity.
    inactive_token_result = {"active": False}
    if token_info == inactive_token_result:
        return token_info

    if token_info is not None:
        subject = g.auth.get("sub")  # OAuth2 subject (if authed via OAuth2)

        # - Callers using the global API secret can introspect any token.
        # - Callers using an OAuth2 access token can only introspect tokens
        #   issued either under their client_id or with their client_id in the
        #   audience.
        token_visible_to_client = (
            # Global API secret was used:
            g.auth["method"] == "global_secret" or
            (
                # OAuth2 access token was used:
                g.auth["method"] == "oauth2" and
                # sanity check that the before_request authoriser did set a subject:
                subject is not None and
                # caller is the OAuth2 client itself:
                subject == g.auth.get("client_id") and
                # introspected token is relevant to this OAuth2 client, as defined above:
                (
                    (subject == token_info.get("client_id")) or
                    (subject in token_info.get("aud", []))
                )
            )
        )
        if token_visible_to_client:
            return token_info

    # If we got to here, the caller isn't entitled to see the token
    # introspection result, so pretend it doesn't exist.
    return inactive_token_result


@app.route("/_debug/whoami")
def whoami():
    """Return authentication info (for debugging purposes)."""
    return g.auth
