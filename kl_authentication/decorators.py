import functools

from rest_framework import status
from rest_framework.response import Response

from . import JSON_CONTENT_TYPE
from .authentication import KairnialTokenAuthentication
from .exceptions import InsufficientPermission
from .services import KairnialAuthServiceError


def handle_auth_ws_error(f):
    """
      Handle WS errors
    """

    @functools.wraps(f)
    def wrapper(request, *args, **kwargs):
        """

        """
        try:
            return f(request, *args, **kwargs)
        except (KairnialAuthServiceError) as e:
            return Response(e.error, content_type=JSON_CONTENT_TYPE,
                            status=status.HTTP_503_SERVICE_UNAVAILABLE)

    return wrapper

def graphql_login_required(f):
    """
    Enforce authentication
    :param f: 
    :return: 
    """

    @functools.wraps((f))
    def wrapper(_, info, *args, **kwargs):
        print(info)
        print(args)
        print(kwargs)

        if not 'request' in info.context:
            raise InsufficientPermission('No authentication context available')
        if not 'client_id' in kwargs:
            raise InsufficientPermission('Invalid client ID')
        request = info.context.get('request')
        request.client_id = kwargs.get('client_id')
        authentication = KairnialTokenAuthentication()
        if not authentication.authenticate(request=request):
            raise InsufficientPermission('You have to be logged in to access these APIs')
        return f(_, info, *args, **kwargs)

    return wrapper
