import functools

from rest_framework import status
from rest_framework.response import Response

from . import JSON_CONTENT_TYPE
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
