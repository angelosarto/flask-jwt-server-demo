from datetime import datetime, timezone, timedelta
import enum
from functools import wraps
import logging

from flask import Flask, request, Response, jsonify, g
import jwt
from flask.ext.cors import CORS

logging.basicConfig(format='%(levelname)s:%(message)s', level=logging.DEBUG)

class AuthorizationResponse(enum.Enum):
    AUTHORIZED = 0,
    EXPIRED_TOKEN = 1,
    INVALID_TOKEN = 2,
    UNAUTHORIZED = 3,
    USER_INVALID = 4

def protected_route(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token_auth, token = verify_token()
        # if token failed return false
        if token_auth != AuthorizationResponse.AUTHORIZED:
            if token_auth == AuthorizationResponse.EXPIRED_TOKEN:
                return jsonify({'error': 'authn_token_expired', 'msg':'token has expired'}), 401
            elif token_auth == AuthorizationResponse.INVALID_TOKEN:
                resp = jsonify({'error': 'authn_token_invalid', 'msg':'token is invalid'})
                resp.headers.add_header('WWW-Authenticate', 'Bearer')
                return resp, 401
            else:
                return jsonify({'error': 'authn_unknown', 'msg':'unknown refresh error'}), 500

        g.user = set_user_object(token)

        access_auth = authorize_request(request, token)
        if access_auth != AuthorizationResponse.AUTHORIZED:
            if access_auth == AuthorizationResponse.UNAUTHORIZED:
                return jsonify({'error': 'authz_unauthorized', 'msg':'User does not have access to this function/object'}), 403
            else:
                return jsonify({'error': 'authz_unknown', 'msg':'unknown authorization error'}), 500
        return f(*args, **kwargs)
    return decorated_function

def authorize_request(request, token):
    # using properties on the token, or use token to lookup user permissions in a DB.
    # then compare to the request

    if request.method == 'GET' and token.get('uid') == 1 \
            and g.user['etc'] == 'etc' \
            and request.path == '/protected_api':
        return AuthorizationResponse.AUTHORIZED
    else:
        return AuthorizationResponse.UNAUTHORIZED

def set_user_object(token):
    # set the flask user from the token, load from the token, lookup in DB, load from redis, etc.
    return {'name': 'joe user', 'uid': token.get('uid'), 'etc': 'etc'}

def verify_token():
    auth = request.headers.get('Authorization', None)
    if auth is None:
        return AuthorizationResponse.INVALID_TOKEN, None

    parts = auth.split()
    if parts[0].lower() != 'bearer':
        return AuthorizationResponse.INVALID_TOKEN, None
    elif len(parts) != 2:
        return AuthorizationResponse.INVALID_TOKEN, None

    try:
        payload = jwt.decode(parts[1], SECRET, algorithms='HS256')
    except jwt.ExpiredSignatureError:
        return AuthorizationResponse.EXPIRED_TOKEN, None
    except jwt.InvalidTokenError:
        return AuthorizationResponse.INVALID_TOKEN, None

    return AuthorizationResponse.AUTHORIZED, payload


app = Flask(__name__)
app.debug = True
CORS(app)
TOKEN_ALG = 'HS256'
SECRET = 'secretX'
TOKEN_TIMEOUT = 15

@app.route('/refresh', methods=['POST'])
def refresh():
    try:
        auth = request.get_json()
        encoded_token = auth.get('token', None)
        token = jwt.decode(encoded_token, 'secretX', algorithms=TOKEN_ALG)
        token['exp'] = int((datetime.now(timezone.utc) + timedelta(seconds=TOKEN_TIMEOUT)).timestamp())
        encoded_token = jwt.encode(token, SECRET, algorithm=TOKEN_ALG)
        return jsonify({'token': encoded_token.decode()})

    except Exception as e:
        resp = jsonify({'error': 'token_refresh_failed', 'msg': str(e)})
        resp.headers.add_header('WWW-Authenticate', 'Bearer')
        return resp, 403

@app.route('/auth', methods=['POST'])
def authenticate():
    auth = request.get_json()
    username = auth.get('username', None)
    password = auth.get('password', None)
    if username == 'joe' and password == 'pass':
        uid = 1
        token = {'uid': uid,
                 'exp': int((datetime.now(timezone.utc) + timedelta(seconds=TOKEN_TIMEOUT)).timestamp()),
               }
        encoded_token = jwt.encode(token, SECRET, algorithm=TOKEN_ALG)
        return jsonify({'token': encoded_token.decode()})

    resp = jsonify({'error': 'authentication_failed', 'msg': 'username/password invalid'})
    resp.headers.add_header('WWW-Authenticate', 'Bearer')
    return resp, 403

@app.route('/open_api')
def open_api():
    msg = {"msg":"this api can be called with nothing"}
    return jsonify(msg)

@app.route('/protected_api')
@protected_route
def protected_api():
    msg = {"msg":"this api requires a token", "accessed_by": g.user['name']}
    return jsonify(msg)

if __name__ == '__main__':
    app.run()
