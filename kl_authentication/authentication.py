# -*- coding: utf-8 -*-

from __future__ import unicode_literals

import logging
import uuid

import jwt
import urllib
from django.conf import settings
from django.contrib.auth import get_user_model
from rest_framework_simplejwt.authentication import JWTAuthentication

KAIRNIAL_AUTH_DOMAIN = settings.KAIRNIAL_AUTH_DOMAIN
KAIRNIAL_AUTH_PUBLIC_KEY = settings.KAIRNIAL_AUTH_PUBLIC_KEY
ALGORITHMS = ["RS256"]


class TokenAthentication(JWTAuthentication):
    """
    Token based authentication using the JSON Web Token standard.
    """

    def _get_m2m_user(self, request):
        """
        Get User from header
        """
        user_id = request.META.get('HTTP_X_APP_USER_ID')
        if not user_id:
            return None
        user = get_user_model()(
            first_name='M2M',
            last_name='User',
            email='none@thinkproject.com'
        )
        user.uuid = user_id
        return user

    def _get_token_user(self, request, token):
        """
        Get user from token information
        """
        payload = jwt.decode(
            token,
            KAIRNIAL_AUTH_PUBLIC_KEY,
            algorithms=ALGORITHMS,
            audience=request.client_id
        )
        uuid = payload.get('sub')
        first_name = ''
        last_name = payload.get('name') or ''
        email = payload.get('email').strip()
        user = get_user_model()(
            first_name=first_name,
            last_name=last_name,
            email=email
        )
        user.uuid = uuid
        return user

    def _get_user(self, request, token):
        """
        Get user information from token or request
        :param request:
        :param token:
        :return:
        """
        logger = logging.getLogger('authentication')
        user = self._get_m2m_user(request=request)
        if user:
            request.user = user
            return user, token
        try:
            user = self._get_token_user(request=request, token=token)
            request.user = user
            return user, token
        except jwt.ExpiredSignatureError:
            logger.error("Token expired")
            return None
        except (jwt.InvalidIssuerError, jwt.InvalidAudienceError):
            logger.error("incorrect claims, please check the audience and issuer")
            return None
        except AttributeError:
            logger.error("Unable to get client_id")
            return None
        except Exception as e:
            logger.error(f"Unable to parse authentication {str(e)}")
            return None


class KairnialTokenAuthentication(TokenAthentication):
    """
    Clients should authenticate by passing the token key in the "Authorization"
    HTTP header, prepended with the string specified in the setting
    `JWT_AUTH_HEADER_PREFIX`. For example:
        Authorization: Bearer eyJhbGciOiAiSFMyNTYiLCAidHlwIj
    """

    def authenticate(self, request):
        """
        Returns a two-tuple of `User` and token if a valid signature has been
        supplied using JWT-based authentication, otherwise, returns `None`.
        """
        logger = logging.getLogger('authentication')
        if getattr(settings, 'TEST_RUN', False):
            user = get_user_model()(
                first_name="Test",
                last_name="User",
                email="test@user.com"
            )
            user.uuid = settings.TEST_USER_ID
            token = str(uuid.uuid4())
            return user, str(token)
        try:
            token = request.META.get('HTTP_AUTHORIZATION').split()[1]
            if token is None:
                logger.error('Authorization header not found')
                return None
        except (AttributeError, IndexError):
            logger.error('Malformed authentication header')
            return None
        return self._get_user(request=request, token=token)


class KairnialCookieAuthentication(TokenAthentication):
    """
    Clients should authenticate by passing the access_token cookie with url encoded jwt
    """

    def authenticate(self, request):
        """
        Returns a two-tuple of `User` and token if a valid signature has been
        supplied using JWT-based authentication, otherwise, returns `None`.
        """
        logger = logging.getLogger('authentication')
        try:
            cookie = request.COOKIES.get('access_token')
            if cookie is None:
                logger.error('access_token cookie not found')
                return None
            token = urllib.parse.unquote(cookie).strip('"')
            if token is None:
                logger.error('access_token cookie not found')
                return None
        except (AttributeError, IndexError):
            logger.error('Malformed access_token cookie')
            return None
        return self._get_user(request=request, token=token)
