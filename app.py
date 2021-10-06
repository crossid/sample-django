import os
from base64 import b64encode
from http import HTTPStatus

from django.conf.urls import url
from django.http import HttpResponse, HttpResponseRedirect, HttpResponseBadRequest, HttpResponseForbidden, HttpResponseNotAllowed
from django.template.loader import render_to_string
from django.utils.decorators import decorator_from_middleware, decorator_from_middleware_with_args
from django.contrib.auth.decorators import login_required
from functools import wraps

from client import OIDCClient

DEBUG = True
SECRET_KEY = b64encode(os.urandom(32)).decode()
ROOT_URLCONF = __name__
TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [
            './templates/'
        ],
    },
]

INSTALLED_APPS = [
    'django.contrib.sessions',
]

MIDDLEWARE = [
    'django.contrib.sessions.middleware.SessionMiddleware',
]

SESSION_ENGINE = 'django.contrib.sessions.backends.file'

client = OIDCClient(os.getenv('ISSUER_BASE_URL'), 
                      os.getenv('CLIENT_ID'), 
                      os.getenv('CLIENT_SECRET'), 
                      os.getenv('REDIRECT_URI'))

def index(request):
    html = render_to_string('index.html')
    return HttpResponse(html)

def login(request):
    nonce = b64encode(os.urandom(32)).decode()
    state = b64encode(os.urandom(32)).decode()

    request.session['nonce'] = nonce
    request.session['state'] = state

    auth_url = client.auth_url(state, scope=['openid', 'profile', 'email', 'offline'], nonce = nonce)

    return HttpResponseRedirect(auth_url)

def handle_callback(request):
    code = request.GET.get('code', '')
    if code == '':
      return HttpResponseBadRequest('bad or missing code')

    state = request.GET.get('state', '')
    if request.session.get('state', '') == '' or request.session['state'] != state:
        return HttpResponseBadRequest('bad state')

    request.session.pop('state')


    tokens = client.exchange_token(code)

    saved_nonce = request.session['nonce']

    id_token = client.decode(tokens.id_token, nonce=saved_nonce)

    logout_url = client.end_session_endpoint + '?id_token_hint=' +  tokens.id_token + '&post_logout_redirect_uri=https://localhost'

    html = render_to_string('post_callback.html', {'name': id_token['name'], 'access_token': tokens.access_token, 'logout_url': logout_url})

    return HttpResponse(html)


class HttpResponseUnauthorized(HttpResponse):
    status_code = HTTPStatus.UNAUTHORIZED

def token_required(f):
    @wraps(f)
    def decorated_function(request, *args, **kwargs):
        print(request.META)
        tok = request.META.get('HTTP_AUTHORIZATION', '')
        if 'Bearer ' not in tok:
            return HttpResponseUnauthorized('missing authorization header')

        token = tok.replace('Bearer ', '')

        nonoce = request.session.get('nonce', '')

        try:
            access_token = client.decode(token, nonce = nonoce)
            request.access_token = access_token
        except Exception as e:
            return HttpResponseUnauthorized(str(e))
      
        return f(request, *args, **kwargs)
    return decorated_function

def scopes_required(scopes):
  def wrapd_function(f):
    @wraps(f)
    def decorated_function(request, *args, **kwargs):
        if request.access_token == None:
                return HttpResponseUnauthorized('missing token')

        if len(set(request.access_token.get('scp', [])).intersection(scopes)) == 0:
            return HttpResponseForbidden('missing scopes')


        return f(request, *args, **kwargs)
    return decorated_function
  return wrapd_function


@token_required
@scopes_required(['profile'])
def protected(request):
    return HttpResponse('You are authorized')

urlpatterns = [
    url(r'^$', index, name='index'),
    url(r'^login$', login, name='login'),
    url(r'^callback$', handle_callback, name='handle_callback'),
    url(r'^protected$', protected, name='protected'),
]