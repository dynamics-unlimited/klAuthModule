"""
Kairnial authentication middleware
"""
import logging

from django.contrib.auth import authenticate


class KairnialAuthMiddleware(object):
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
        # GET TOKEN
        logger = logging.getLogger('authentication')
        try:
            logger.debug("adding token and user attributes to request")
            request.token = request.META.get('HTTP_AUTHORIZATION').split()[1]
            request.user_id = request.META.get('HTTP_X_APP_USER_ID')
        except (AttributeError, IndexError) as e:
            logger.warning(str(e))
            pass
        response = self.get_response(request)
        return response

    @staticmethod
    def process_view(request, view_func, view_args, view_kwargs):
        client_id = view_kwargs.get('client_id', None)
        if client_id:
            request.client_id = client_id
