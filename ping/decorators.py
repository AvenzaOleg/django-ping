from functools import wraps
import base64

from django.http import HttpResponse
from django.contrib.auth import (
    authenticate,
    login
)
from django.conf import settings

from ping.defaults import PING_BASIC_AUTH


def http_basic_auth(func):
    """
    Attempts to login user with u/p provided in HTTP_AUTHORIZATION header.
    If successful, returns the view, otherwise returns a 401.
    If PING_BASIC_AUTH is False, then just return the view function 
    
    Modified code by:
    http://djangosnippets.org/users/bthomas/
    from
    http://djangosnippets.org/snippets/1304/
    """

    @wraps(func)
    def _decorator(request, *args, **kwargs):
        if getattr(settings, 'PING_BASIC_AUTH', PING_BASIC_AUTH):
            if 'username' in request.GET and 'password' in request.GET:
                if (request.GET['username'], request.GET['password']) == settings.PING_BASIC_AUTH:
                    return func(request, *args, **kwargs)

            if 'HTTP_AUTHORIZATION' in request.META:
                authmeth, auth = request.META['HTTP_AUTHORIZATION'].split(' ', 1)
                if authmeth.lower() == 'basic':
                    # strip whitespace
                    auth = auth.strip()
                    
                    # Decode base64: String -> Binary -> Base64Decode -> Binary -> String
                    auth = base64.standard_b64decode(auth.encode('ascii')).decode('utf-8')
                    
                    username, password = auth.split(':', 1)

                    if (username, password) == tuple(settings.PING_BASIC_AUTH):
                        return func(request, *args, **kwargs)
                    else:
                        response = HttpResponse("Invalid Credentials")
                        response.status_code = 403
                        return response

            else:
                response = HttpResponse("Invalid Credentials")
                response.status_code = 401
                response['WWW-Authenticate'] = 'Basic realm=""Invalid Credentials""'
                return response
        else:
            return func(request, *args, **kwargs)

    return _decorator
