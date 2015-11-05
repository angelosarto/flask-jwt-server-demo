import datetime
import enum
from functools import wraps
import logging

from flask import Flask, request, Response
import jwt
from flask.ext.cors import CORS


logging.basicConfig(format='%(levelname)s:%(message)s', level=logging.DEBUG)

class AuthorizationResponse(enum.Enum):
    AUTHORIZED = 0,
    EXPIRED_TOKEN = 1,
    INVALID_TOKEN = 2,
    UNAUTHORIZED = 3,
    USER_INVALID = 4


class Permission(enum.Enum):
    READ = 0,
    WRITE = 1,
    ADMIN = 2,


def authenticate_user(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # logging.debug("kwargs: {}".format(kwargs))
        auth, token = verify_token()
        # if token failed return false
        if auth != AuthorizationResponse.AUTHORIZED:
            if auth == AuthorizationResponse.EXPIRED_TOKEN:
                return Response("Token has expired", status=401)
            if auth == AuthorizationResponse.INVALID_TOKEN:
                return Response("Token is invalid", status=401, headers={'WWW-Authenticate': 'Bearer'})
        user = lite_load_user_perm(token.get('uid'))
        kwargs['CURRENT_USER'] = user
        return f(*args, **kwargs)
    return decorated_function


def lite_load_user_perm(uid):
    return "User info for{}".format(uid)


def verify_access(userinfo, params):
    return True, None


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
    except jwt.InvalidTokenError as e:
        return AuthorizationResponse.INVALID_TOKEN, None

    return AuthorizationResponse.AUTHORIZED, payload


app = Flask(__name__)
app.debug = True
CORS(app)
SECRET = 'secretX'

@app.route('/auth2', methods=['POST'])
def authenticate2():
    print("hello")
    return

@app.route('/auth', methods=['POST'])
def authenticate():
    auth = request.get_json()
    username = auth.get('username', None)
    password = auth.get('password', None)
    if username == 'joe' and password == 'pass':
        uid = 1
        token = {'uid': uid,
                 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=10),
               }
        return jwt.encode(token, SECRET, algorithm='HS256')

    return "Auth Failed", 403

@app.route('/protected/<p1>')
@authenticate_user  #user object willbe added to end of call
def protected(p1, CURRENT_USER):
    authorized, cause = verify_access(CURRENT_USER, "some mapping of permission and object")
    if not authorized:
        return Response("You do not have permission to access this function:{}".format(cause), status=403)

    return 'Success!'

@app.route('/')
def open():
    return 'Open Area!'

if __name__ == '__main__':
    app.run()