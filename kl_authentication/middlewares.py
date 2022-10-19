"""
Kairnial authentication middleware
"""
import logging
import urllib

from django.contrib.auth import authenticate


class KairnialRequestMiddleware:
    """
    Set token and user_id on request
    """
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        logger = logging.getLogger('authentication')
        logger.debug("Setting token and user_id on request")
        request.token = None
        request.user_id = None
        response = self.get_response(request)
        return response


class KairnialTokenAuthMiddleware(object):
    """
    Check the jwt token passed by the request
    """

    def __init__(self, get_response):
        self.get_response = get_response

    @staticmethod
    def jwt_get_username_from_payload_handler(payload):
        username = payload.get('sub').replace('|', '.')
        authenticate(remote_user=username)
        return username

    def __call__(self, request):
        # Get TOKEN from header
        logger = logging.getLogger('authentication')
        try:
            request.token = request.META.get('HTTP_AUTHORIZATION').split()[1]
            logger.debug(f"set token on request: {request.token}")
            request.user_id = request.META.get('HTTP_X_APP_USER_ID')
            logger.debug(f"set user_id on request: {request.user_id}")
        except (AttributeError, IndexError) as e:
            logger.warning(str(e))
        response = self.get_response(request)
        return response

    @staticmethod
    def process_view(request, view_func, view_args, view_kwargs):
        client_id = view_kwargs.get('client_id', None)
        if client_id:
            request.client_id = client_id


class KairnialCookieAuthMiddleware(object):
    """
    Check the jwt token passed by the request
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Get TOKEN from cookie
        logger = logging.getLogger('authentication')
        try:
            cookie = request.COOKIES.get('access_token')
            if cookie:
                logger.debug(f"set token on request: {request.token}")
                request.token = urllib.parse.unquote(cookie).strip('"')
                logger.debug(f"set user_id on request to None")
                request.user_id = None # user_id should not be set if cookie is involved
        except (AttributeError, IndexError) as e:
            logger.warning(str(e))
        response = self.get_response(request)
        return response

    @staticmethod
    def process_view(request, view_func, view_args, view_kwargs):
        client_id = view_kwargs.get('client_id', None)
        if client_id:
            request.client_id = client_id